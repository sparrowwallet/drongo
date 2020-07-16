package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Script;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.sparrowwallet.drongo.psbt.PSBTEntry.parseKeyDerivation;

public class PSBTOutput {
    public static final byte PSBT_OUT_REDEEM_SCRIPT = 0x00;
    public static final byte PSBT_OUT_WITNESS_SCRIPT = 0x01;
    public static final byte PSBT_OUT_BIP32_DERIVATION = 0x02;
    public static final byte PSBT_OUT_PROPRIETARY = (byte)0xfc;

    private Script redeemScript;
    private Script witnessScript;
    private final Map<ECKey, KeyDerivation> derivedPublicKeys = new LinkedHashMap<>();
    private final Map<String, String> proprietary = new LinkedHashMap<>();

    private static final Logger log = LoggerFactory.getLogger(PSBTOutput.class);

    PSBTOutput(Script redeemScript, Script witnessScript, Map<ECKey, KeyDerivation> derivedPublicKeys, Map<String, String> proprietary) {
        this.redeemScript = redeemScript;
        this.witnessScript = witnessScript;
        this.derivedPublicKeys.putAll(derivedPublicKeys);
        this.proprietary.putAll(proprietary);
    }

    PSBTOutput(List<PSBTEntry> outputEntries) throws PSBTParseException {
        for(PSBTEntry entry : outputEntries) {
            switch (entry.getKeyType()) {
                case PSBT_OUT_REDEEM_SCRIPT:
                    entry.checkOneByteKey();
                    Script redeemScript = new Script(entry.getData());
                    this.redeemScript = redeemScript;
                    log.debug("Found output redeem script hex " + Hex.toHexString(redeemScript.getProgram()) + " script " + redeemScript);
                    break;
                case PSBT_OUT_WITNESS_SCRIPT:
                    entry.checkOneByteKey();
                    Script witnessScript = new Script(entry.getData());
                    this.witnessScript = witnessScript;
                    log.debug("Found output witness script hex " + Hex.toHexString(witnessScript.getProgram()) + " script " + witnessScript);
                    break;
                case PSBT_OUT_BIP32_DERIVATION:
                    entry.checkOneBytePlusPubKey();
                    ECKey derivedPublicKey = ECKey.fromPublicOnly(entry.getKeyData());
                    KeyDerivation keyDerivation = parseKeyDerivation(entry.getData());
                    this.derivedPublicKeys.put(derivedPublicKey, keyDerivation);
                    log.debug("Found output bip32_derivation with master fingerprint " + keyDerivation.getMasterFingerprint() + " at path " + keyDerivation.getDerivationPath() + " public key " + derivedPublicKey);
                    break;
                case PSBT_OUT_PROPRIETARY:
                    proprietary.put(Hex.toHexString(entry.getKeyData()), Hex.toHexString(entry.getData()));
                    log.debug("Found proprietary output " + Hex.toHexString(entry.getKeyData()) + ": " + Hex.toHexString(entry.getData()));
                    break;
                default:
                    log.warn("PSBT output not recognized key type: " + entry.getKeyType());
            }
        }
    }

    public Script getRedeemScript() {
        return redeemScript;
    }

    public Script getWitnessScript() {
        return witnessScript;
    }

    public KeyDerivation getKeyDerivation(ECKey publicKey) {
        return derivedPublicKeys.get(publicKey);
    }

    public Map<ECKey, KeyDerivation> getDerivedPublicKeys() {
        return derivedPublicKeys;
    }

    public Map<String, String> getProprietary() {
        return proprietary;
    }
}
