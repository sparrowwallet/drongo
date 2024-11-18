package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static com.sparrowwallet.drongo.protocol.ScriptType.*;
import static com.sparrowwallet.drongo.psbt.PSBTEntry.*;

public class PSBTOutput {
    public static final byte PSBT_OUT_REDEEM_SCRIPT = 0x00;
    public static final byte PSBT_OUT_WITNESS_SCRIPT = 0x01;
    public static final byte PSBT_OUT_BIP32_DERIVATION = 0x02;
    public static final byte PSBT_OUT_AMOUNT = 0x03;
    public static final byte PSBT_OUT_SCRIPT = 0x04;
    public static final byte PSBT_OUT_TAP_INTERNAL_KEY = 0x05;
    public static final byte PSBT_OUT_TAP_BIP32_DERIVATION = 0x07;
    public static final byte PSBT_OUT_PROPRIETARY = (byte)0xfc;

    private Script redeemScript;
    private Script witnessScript;
    private final Map<ECKey, KeyDerivation> derivedPublicKeys = new LinkedHashMap<>();
    private final Map<String, String> proprietary = new LinkedHashMap<>();
    private Map<ECKey, Map<KeyDerivation, List<Sha256Hash>>> tapDerivedPublicKeys = new LinkedHashMap<>();
    private ECKey tapInternalKey;

    //PSBTv2 fields
    private Long amount;
    private Script script;

    private static final Logger log = LoggerFactory.getLogger(PSBTOutput.class);

    private final PSBT psbt;
    private int index;

    PSBTOutput(PSBT psbt, int index) {
        this.psbt = psbt;
        this.index = index;
    }

    PSBTOutput(PSBT psbt, int index, ScriptType scriptType, Script redeemScript, Script witnessScript, Map<ECKey, KeyDerivation> derivedPublicKeys, Map<String, String> proprietary, ECKey tapInternalKey) {
        this(psbt, index);

        this.redeemScript = redeemScript;
        this.witnessScript = witnessScript;

        if(scriptType != P2TR) {
            this.derivedPublicKeys.putAll(derivedPublicKeys);
        }

        this.proprietary.putAll(proprietary);

        this.tapInternalKey = tapInternalKey == null ? null : ECKey.fromPublicOnly(tapInternalKey.getPubKeyXCoord());

        if(tapInternalKey != null && !derivedPublicKeys.values().isEmpty()) {
            KeyDerivation tapKeyDerivation = derivedPublicKeys.values().iterator().next();
            tapDerivedPublicKeys.put(this.tapInternalKey, Map.of(tapKeyDerivation, Collections.emptyList()));
        }
    }

    PSBTOutput(PSBT psbt, List<PSBTEntry> outputEntries, int index) throws PSBTParseException {
        this(psbt, index);
        for(PSBTEntry entry : outputEntries) {
            switch((byte)entry.getKeyType()) {
                case PSBT_OUT_REDEEM_SCRIPT:
                    entry.checkOneByteKey();
                    Script redeemScript = new Script(entry.getData());
                    this.redeemScript = redeemScript;
                    log.debug("Found output redeem script hex " + Utils.bytesToHex(redeemScript.getProgram()) + " script " + redeemScript);
                    break;
                case PSBT_OUT_WITNESS_SCRIPT:
                    entry.checkOneByteKey();
                    Script witnessScript = new Script(entry.getData());
                    this.witnessScript = witnessScript;
                    log.debug("Found output witness script hex " + Utils.bytesToHex(witnessScript.getProgram()) + " script " + witnessScript);
                    break;
                case PSBT_OUT_BIP32_DERIVATION:
                    entry.checkOneBytePlusPubKey();
                    ECKey derivedPublicKey = ECKey.fromPublicOnly(entry.getKeyData());
                    KeyDerivation keyDerivation = parseKeyDerivation(entry.getData());
                    this.derivedPublicKeys.put(derivedPublicKey, keyDerivation);
                    log.debug("Found output bip32_derivation with master fingerprint " + keyDerivation.getMasterFingerprint() + " at path " + keyDerivation.getDerivationPath() + " public key " + derivedPublicKey);
                    break;
                case PSBT_OUT_AMOUNT:
                    entry.checkOneByteKey();
                    this.amount = Utils.readInt64(entry.getData(), 0);
                    log.debug("Found output amount " + this.amount);
                    break;
                case PSBT_OUT_SCRIPT:
                    entry.checkOneByteKey();
                    Script script = new Script(entry.getData());
                    this.script = script;
                    log.debug("Found output script hex " + Utils.bytesToHex(script.getProgram()) + " script " + script);
                    break;
                case PSBT_OUT_PROPRIETARY:
                    proprietary.put(Utils.bytesToHex(entry.getKeyData()), Utils.bytesToHex(entry.getData()));
                    log.debug("Found proprietary output " + Utils.bytesToHex(entry.getKeyData()) + ": " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_OUT_TAP_INTERNAL_KEY:
                    entry.checkOneByteKey();
                    this.tapInternalKey = ECKey.fromPublicOnly(entry.getData());
                    log.debug("Found output taproot internal key " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_OUT_TAP_BIP32_DERIVATION:
                    entry.checkOneBytePlusXOnlyPubKey();
                    ECKey tapPublicKey = ECKey.fromPublicOnly(entry.getKeyData());
                    Map<KeyDerivation, List<Sha256Hash>> tapKeyDerivations = parseTaprootKeyDerivation(entry.getData());
                    if(tapKeyDerivations.isEmpty()) {
                        log.warn("PSBT provided an invalid output taproot key derivation");
                    } else {
                        this.tapDerivedPublicKeys.put(tapPublicKey, tapKeyDerivations);
                        for(KeyDerivation tapKeyDerivation : tapKeyDerivations.keySet()) {
                            log.debug("Found output taproot key derivation for key " + Utils.bytesToHex(entry.getKeyData()) + " with master fingerprint " + tapKeyDerivation.getMasterFingerprint() + " at path " + tapKeyDerivation.getDerivationPath());
                        }
                    }
                    break;
                default:
                    log.warn("PSBT output not recognized key type: " + entry.getKeyType());
            }
        }
    }

    public List<PSBTEntry> getOutputEntries(int psbtVersion) {
        List<PSBTEntry> entries = new ArrayList<>();

        if(redeemScript != null) {
            entries.add(populateEntry(PSBT_OUT_REDEEM_SCRIPT, null, redeemScript.getProgram()));
        }

        if(witnessScript != null) {
            entries.add(populateEntry(PSBT_OUT_WITNESS_SCRIPT, null, witnessScript.getProgram()));
        }

        for(Map.Entry<ECKey, KeyDerivation> entry : derivedPublicKeys.entrySet()) {
            entries.add(populateEntry(PSBT_OUT_BIP32_DERIVATION, entry.getKey().getPubKey(), serializeKeyDerivation(entry.getValue())));
        }

        if(psbtVersion >= 2) {
            if(amount != null) {
                byte[] amountBytes = new byte[8];
                Utils.int64ToByteArrayLE(amount, amountBytes, 0);
                entries.add(populateEntry(PSBT_OUT_AMOUNT, null, amountBytes));
            }
            if(script != null) {
                entries.add(populateEntry(PSBT_OUT_SCRIPT, null, script.getProgram()));
            }
        }

        for(Map.Entry<String, String> entry : proprietary.entrySet()) {
            entries.add(populateEntry(PSBT_OUT_PROPRIETARY, Utils.hexToBytes(entry.getKey()), Utils.hexToBytes(entry.getValue())));
        }

        for(Map.Entry<ECKey, Map<KeyDerivation, List<Sha256Hash>>> entry : tapDerivedPublicKeys.entrySet()) {
            if(!entry.getValue().isEmpty()) {
                entries.add(populateEntry(PSBT_OUT_TAP_BIP32_DERIVATION, entry.getKey().getPubKeyXCoord(), serializeTaprootKeyDerivation(Collections.emptyList(), entry.getValue().keySet().iterator().next())));
            }
        }

        if(tapInternalKey != null) {
            entries.add(populateEntry(PSBT_OUT_TAP_INTERNAL_KEY, null, tapInternalKey.getPubKeyXCoord()));
        }

        return entries;
    }

    void combine(PSBTOutput psbtOutput) {
        if(psbtOutput.redeemScript != null) {
            redeemScript = psbtOutput.redeemScript;
        }

        if(psbtOutput.witnessScript != null) {
            witnessScript = psbtOutput.witnessScript;
        }

        derivedPublicKeys.putAll(psbtOutput.derivedPublicKeys);

        if(psbtOutput.amount != null) {
            amount = psbtOutput.amount;
        }

        if(psbtOutput.script != null) {
            script = psbtOutput.script;
        }

        proprietary.putAll(psbtOutput.proprietary);

        tapDerivedPublicKeys.putAll(psbtOutput.tapDerivedPublicKeys);

        if(psbtOutput.tapInternalKey != null) {
            tapInternalKey = psbtOutput.tapInternalKey;
        }
    }

    public Script getRedeemScript() {
        return redeemScript;
    }

    public void setRedeemScript(Script redeemScript) {
        this.redeemScript = redeemScript;
    }

    public Script getWitnessScript() {
        return witnessScript;
    }

    public void setWitnessScript(Script witnessScript) {
        this.witnessScript = witnessScript;
    }

    public KeyDerivation getKeyDerivation(ECKey publicKey) {
        return derivedPublicKeys.get(publicKey);
    }

    public Map<ECKey, KeyDerivation> getDerivedPublicKeys() {
        return derivedPublicKeys;
    }

    public Long getAmount() {
        if(psbt.getPsbtVersion() >= 2) {
            return amount;
        }

        return getOutput().getValue();
    }

    Long amount() {
        return amount;
    }

    public void setAmount(Long amount) {
        this.amount = amount;
    }

    public Script getScript() {
        if(psbt.getPsbtVersion() >= 2) {
            return script;
        }

        return getOutput().getScript();
    }

    Script script() {
        return script;
    }

    public void setScript(Script script) {
        this.script = script;
    }

    public Map<String, String> getProprietary() {
        return proprietary;
    }

    public Map<ECKey, Map<KeyDerivation, List<Sha256Hash>>> getTapDerivedPublicKeys() {
        return tapDerivedPublicKeys;
    }

    public void setTapDerivedPublicKeys(Map<ECKey, Map<KeyDerivation, List<Sha256Hash>>> tapDerivedPublicKeys) {
        this.tapDerivedPublicKeys = tapDerivedPublicKeys;
    }

    public ECKey getTapInternalKey() {
        return tapInternalKey;
    }

    public void setTapInternalKey(ECKey tapInternalKey) {
        this.tapInternalKey = tapInternalKey;
    }

    public TransactionOutput getOutput() {
        return psbt.getTransaction().getOutputs().get(index);
    }

    void setIndex(int index) {
        this.index = index;
    }

    public void clearNonFinalFields() {
        tapDerivedPublicKeys.clear();
    }
}
