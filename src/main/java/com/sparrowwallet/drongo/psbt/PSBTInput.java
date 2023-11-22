package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static com.sparrowwallet.drongo.protocol.ScriptType.*;
import static com.sparrowwallet.drongo.protocol.TransactionSignature.Type.*;
import static com.sparrowwallet.drongo.psbt.PSBTEntry.*;

public class PSBTInput {
    public static final byte PSBT_IN_NON_WITNESS_UTXO = 0x00;
    public static final byte PSBT_IN_WITNESS_UTXO = 0x01;
    public static final byte PSBT_IN_PARTIAL_SIG = 0x02;
    public static final byte PSBT_IN_SIGHASH_TYPE = 0x03;
    public static final byte PSBT_IN_REDEEM_SCRIPT = 0x04;
    public static final byte PSBT_IN_WITNESS_SCRIPT = 0x05;
    public static final byte PSBT_IN_BIP32_DERIVATION = 0x06;
    public static final byte PSBT_IN_FINAL_SCRIPTSIG = 0x07;
    public static final byte PSBT_IN_FINAL_SCRIPTWITNESS = 0x08;
    public static final byte PSBT_IN_POR_COMMITMENT = 0x09;
    public static final byte PSBT_IN_PROPRIETARY = (byte)0xfc;
    public static final byte PSBT_IN_TAP_KEY_SIG = 0x13;
    public static final byte PSBT_IN_TAP_BIP32_DERIVATION = 0x16;
    public static final byte PSBT_IN_TAP_INTERNAL_KEY = 0x17;

    private final PSBT psbt;
    private Transaction nonWitnessUtxo;
    private TransactionOutput witnessUtxo;
    private final Map<ECKey, TransactionSignature> partialSignatures = new LinkedHashMap<>();
    private SigHash sigHash;
    private Script redeemScript;
    private Script witnessScript;
    private final Map<ECKey, KeyDerivation> derivedPublicKeys = new LinkedHashMap<>();
    private Script finalScriptSig;
    private TransactionWitness finalScriptWitness;
    private String porCommitment;
    private final Map<String, String> proprietary = new LinkedHashMap<>();
    private TransactionSignature tapKeyPathSignature;
    private Map<ECKey, Map<KeyDerivation, List<Sha256Hash>>> tapDerivedPublicKeys = new LinkedHashMap<>();
    private ECKey tapInternalKey;

    private final Transaction transaction;
    private int index;

    private static final Logger log = LoggerFactory.getLogger(PSBTInput.class);

    PSBTInput(PSBT psbt, Transaction transaction, int index) {
        this.psbt = psbt;
        this.transaction = transaction;
        this.index = index;
    }

    PSBTInput(PSBT psbt, ScriptType scriptType, Transaction transaction, int index, Transaction utxo, int utxoIndex, Script redeemScript, Script witnessScript, Map<ECKey, KeyDerivation> derivedPublicKeys, Map<String, String> proprietary, ECKey tapInternalKey, boolean alwaysAddNonWitnessTx) {
        this(psbt, transaction, index);

        if(Arrays.asList(ScriptType.WITNESS_TYPES).contains(scriptType)) {
            this.witnessUtxo = utxo.getOutputs().get(utxoIndex);
        } else {
            this.nonWitnessUtxo = utxo;
        }

        if(alwaysAddNonWitnessTx) {
            //Add non-witness UTXO to segwit types to handle Trezor, Bitbox and Ledger requirements
            this.nonWitnessUtxo = utxo;
        }

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

        this.sigHash = getDefaultSigHash();
    }

    PSBTInput(PSBT psbt, List<PSBTEntry> inputEntries, Transaction transaction, int index) throws PSBTParseException {
        this.psbt = psbt;
        for(PSBTEntry entry : inputEntries) {
            switch(entry.getKeyType()) {
                case PSBT_IN_NON_WITNESS_UTXO:
                    entry.checkOneByteKey();
                    Transaction nonWitnessTx = new Transaction(entry.getData());
                    nonWitnessTx.verify();
                    Sha256Hash inputHash = nonWitnessTx.calculateTxId(false);
                    Sha256Hash outpointHash = transaction.getInputs().get(index).getOutpoint().getHash();
                    if(!outpointHash.equals(inputHash)) {
                        throw new PSBTParseException("Hash of provided non witness utxo transaction " + inputHash + " does not match transaction input outpoint hash " + outpointHash + " at index " + index);
                    }

                    this.nonWitnessUtxo = nonWitnessTx;
                    log.debug("Found input non witness utxo with txid: " + nonWitnessTx.getTxId() + " version " + nonWitnessTx.getVersion() + " size " + nonWitnessTx.getMessageSize() + " locktime " + nonWitnessTx.getLocktime());
                    for(TransactionInput input: nonWitnessTx.getInputs()) {
                        log.debug(" Transaction input references txid: " + input.getOutpoint().getHash() + " vout " + input.getOutpoint().getIndex() + " with script " + input.getScriptSig());
                    }
                    for(TransactionOutput output: nonWitnessTx.getOutputs()) {
                        log.debug(" Transaction output value: " + output.getValue() + (output.getScript().getToAddress() != null ? " to address " + output.getScript().getToAddress() : "") + " with script hex " + Utils.bytesToHex(output.getScript().getProgram()) + " to script " + output.getScript());
                    }
                    break;
                case PSBT_IN_WITNESS_UTXO:
                    entry.checkOneByteKey();
                    TransactionOutput witnessTxOutput = new TransactionOutput(null, entry.getData(), 0);
                    if(!P2SH.isScriptType(witnessTxOutput.getScript()) && !P2WPKH.isScriptType(witnessTxOutput.getScript()) && !P2WSH.isScriptType(witnessTxOutput.getScript()) && !P2TR.isScriptType(witnessTxOutput.getScript())) {
                        throw new PSBTParseException("Witness UTXO provided for non-witness or unknown input");
                    }
                    this.witnessUtxo = witnessTxOutput;
                    try {
                        log.debug("Found input witness utxo amount " + witnessTxOutput.getValue() + " script hex " + Utils.bytesToHex(witnessTxOutput.getScript().getProgram()) + " script " + witnessTxOutput.getScript() + " addresses " + Arrays.asList(witnessTxOutput.getScript().getToAddresses()));
                    } catch(NonStandardScriptException e) {
                        log.error("Unknown script type", e);
                    }
                    break;
                case PSBT_IN_PARTIAL_SIG:
                    entry.checkOneBytePlusPubKey();
                    ECKey sigPublicKey = ECKey.fromPublicOnly(entry.getKeyData());
                    if(entry.getData().length == 64 || entry.getData().length == 65) {
                        log.error("Schnorr signature provided as ECDSA partial signature, ignoring");
                        break;
                    }
                    //TODO: Verify signature
                    TransactionSignature signature = TransactionSignature.decodeFromBitcoin(ECDSA, entry.getData(), true);
                    this.partialSignatures.put(sigPublicKey, signature);
                    log.debug("Found input partial signature with public key " + sigPublicKey + " signature " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_SIGHASH_TYPE:
                    entry.checkOneByteKey();
                    long sighashType = Utils.readUint32(entry.getData(), 0);
                    SigHash sigHash = SigHash.fromByte((byte)sighashType);
                    this.sigHash = sigHash;
                    log.debug("Found input sighash_type " + sigHash.toString());
                    break;
                case PSBT_IN_REDEEM_SCRIPT:
                    entry.checkOneByteKey();
                    Script redeemScript = new Script(entry.getData());
                    Script scriptPubKey = null;
                    if(this.nonWitnessUtxo != null) {
                        scriptPubKey = this.nonWitnessUtxo.getOutputs().get((int)transaction.getInputs().get(index).getOutpoint().getIndex()).getScript();
                    } else if(this.witnessUtxo != null) {
                        scriptPubKey = this.witnessUtxo.getScript();
                        if(!P2WPKH.isScriptType(redeemScript) && !P2WSH.isScriptType(redeemScript)) { //Witness UTXO should only be provided for P2SH-P2WPKH or P2SH-P2WSH
                            throw new PSBTParseException("Witness UTXO provided but redeem script is not P2WPKH or P2WSH");
                        }
                    }
                    if(scriptPubKey == null) {
                        log.warn("PSBT provided a redeem script for a transaction output that was not provided");
                    } else {
                        if(!P2SH.isScriptType(scriptPubKey)) {
                            throw new PSBTParseException("PSBT provided a redeem script for a transaction output that does not need one");
                        }
                        if(!Arrays.equals(Utils.sha256hash160(redeemScript.getProgram()), scriptPubKey.getPubKeyHash())) {
                            throw new PSBTParseException("Redeem script hash does not match transaction output script pubkey hash " + Utils.bytesToHex(scriptPubKey.getPubKeyHash()));
                        }
                    }

                    this.redeemScript = redeemScript;
                    log.debug("Found input redeem script hex " + Utils.bytesToHex(redeemScript.getProgram()) + " script " + redeemScript);
                    break;
                case PSBT_IN_WITNESS_SCRIPT:
                    entry.checkOneByteKey();
                    Script witnessScript = new Script(entry.getData());
                    byte[] pubKeyHash = null;
                    if(this.redeemScript != null && P2WSH.isScriptType(this.redeemScript)) { //P2SH-P2WSH
                        pubKeyHash = this.redeemScript.getPubKeyHash();
                    } else if(this.witnessUtxo != null && P2WSH.isScriptType(this.witnessUtxo.getScript())) { //P2WSH
                        pubKeyHash = this.witnessUtxo.getScript().getPubKeyHash();
                    }
                    if(pubKeyHash == null) {
                        log.warn("Witness script provided without P2WSH witness utxo or P2SH redeem script");
                    } else if(!Arrays.equals(Sha256Hash.hash(witnessScript.getProgram()), pubKeyHash)) {
                        throw new PSBTParseException("Witness script hash does not match provided pay to script hash " + Utils.bytesToHex(pubKeyHash));
                    }
                    this.witnessScript = witnessScript;
                    log.debug("Found input witness script hex " + Utils.bytesToHex(witnessScript.getProgram()) + " script " + witnessScript);
                    break;
                case PSBT_IN_BIP32_DERIVATION:
                    entry.checkOneBytePlusPubKey();
                    ECKey derivedPublicKey = ECKey.fromPublicOnly(entry.getKeyData());
                    KeyDerivation keyDerivation = parseKeyDerivation(entry.getData());
                    this.derivedPublicKeys.put(derivedPublicKey, keyDerivation);
                    log.debug("Found input bip32_derivation with master fingerprint " + keyDerivation.getMasterFingerprint() + " at path " + keyDerivation.getDerivationPath() + " public key " + derivedPublicKey);
                    break;
                case PSBT_IN_FINAL_SCRIPTSIG:
                    entry.checkOneByteKey();
                    Script finalScriptSig = new Script(entry.getData());
                    this.finalScriptSig = finalScriptSig;
                    log.debug("Found input final scriptSig script hex " + Utils.bytesToHex(finalScriptSig.getProgram()) + " script " + finalScriptSig.toString());
                    break;
                case PSBT_IN_FINAL_SCRIPTWITNESS:
                    entry.checkOneByteKey();
                    TransactionWitness finalScriptWitness = new TransactionWitness(null, entry.getData(), 0);
                    this.finalScriptWitness = finalScriptWitness;
                    log.debug("Found input final scriptWitness " + finalScriptWitness.toString());
                    break;
                case PSBT_IN_POR_COMMITMENT:
                    entry.checkOneByteKey();
                    String porMessage = new String(entry.getData(), StandardCharsets.UTF_8);
                    this.porCommitment = porMessage;
                    log.debug("Found input POR commitment message " + porMessage);
                    break;
                case PSBT_IN_PROPRIETARY:
                    this.proprietary.put(Utils.bytesToHex(entry.getKeyData()), Utils.bytesToHex(entry.getData()));
                    log.debug("Found proprietary input " + Utils.bytesToHex(entry.getKeyData()) + ": " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_TAP_KEY_SIG:
                    entry.checkOneByteKey();
                    this.tapKeyPathSignature = TransactionSignature.decodeFromBitcoin(SCHNORR, entry.getData(), true);
                    log.debug("Found input taproot key path signature " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_TAP_BIP32_DERIVATION:
                    entry.checkOneBytePlusXOnlyPubKey();
                    ECKey tapPublicKey = ECKey.fromPublicOnly(entry.getKeyData());
                    Map<KeyDerivation, List<Sha256Hash>> tapKeyDerivations = parseTaprootKeyDerivation(entry.getData());
                    if(tapKeyDerivations.isEmpty()) {
                        log.warn("PSBT provided an invalid input taproot key derivation");
                    } else {
                        this.tapDerivedPublicKeys.put(tapPublicKey, tapKeyDerivations);
                        for(KeyDerivation tapKeyDerivation : tapKeyDerivations.keySet()) {
                            log.debug("Found input taproot key derivation for key " + Utils.bytesToHex(entry.getKeyData()) + " with master fingerprint " + tapKeyDerivation.getMasterFingerprint() + " at path " + tapKeyDerivation.getDerivationPath());
                        }
                    }
                    break;
                case PSBT_IN_TAP_INTERNAL_KEY:
                    entry.checkOneByteKey();
                    this.tapInternalKey = ECKey.fromPublicOnly(entry.getData());
                    log.debug("Found input taproot internal key " + Utils.bytesToHex(entry.getData()));
                    break;
                default:
                    log.warn("PSBT input not recognized key type: " + entry.getKeyType());
            }
        }

        this.transaction = transaction;
        this.index = index;
    }

    public List<PSBTEntry> getInputEntries() {
        List<PSBTEntry> entries = new ArrayList<>();

        if(nonWitnessUtxo != null) {
            //Serialize all nonWitnessUtxo fields without witness data (pre-Segwit serialization) to reduce PSBT size
            entries.add(populateEntry(PSBT_IN_NON_WITNESS_UTXO, null, nonWitnessUtxo.bitcoinSerialize(false)));
        }

        if(witnessUtxo != null) {
            entries.add(populateEntry(PSBT_IN_WITNESS_UTXO, null, witnessUtxo.bitcoinSerialize()));
        }

        for(Map.Entry<ECKey, TransactionSignature> entry : partialSignatures.entrySet()) {
            entries.add(populateEntry(PSBT_IN_PARTIAL_SIG, entry.getKey().getPubKey(), entry.getValue().encodeToBitcoin()));
        }

        if(sigHash != null) {
            byte[] sigHashBytes = new byte[4];
            Utils.uint32ToByteArrayLE(sigHash.intValue(), sigHashBytes, 0);
            entries.add(populateEntry(PSBT_IN_SIGHASH_TYPE, null, sigHashBytes));
        }

        if(redeemScript != null) {
            entries.add(populateEntry(PSBT_IN_REDEEM_SCRIPT, null, redeemScript.getProgram()));
        }

        if(witnessScript != null) {
            entries.add(populateEntry(PSBT_IN_WITNESS_SCRIPT, null, witnessScript.getProgram()));
        }

        for(Map.Entry<ECKey, KeyDerivation> entry : derivedPublicKeys.entrySet()) {
            entries.add(populateEntry(PSBT_IN_BIP32_DERIVATION, entry.getKey().getPubKey(), serializeKeyDerivation(entry.getValue())));
        }

        if(finalScriptSig != null) {
            entries.add(populateEntry(PSBT_IN_FINAL_SCRIPTSIG, null, finalScriptSig.getProgram()));
        }

        if(finalScriptWitness != null) {
            entries.add(populateEntry(PSBT_IN_FINAL_SCRIPTWITNESS, null, finalScriptWitness.toByteArray()));
        }

        if(porCommitment != null) {
            entries.add(populateEntry(PSBT_IN_POR_COMMITMENT, null, porCommitment.getBytes(StandardCharsets.UTF_8)));
        }

        for(Map.Entry<String, String> entry : proprietary.entrySet()) {
            entries.add(populateEntry(PSBT_IN_PROPRIETARY, Utils.hexToBytes(entry.getKey()), Utils.hexToBytes(entry.getValue())));
        }

        if(tapKeyPathSignature != null) {
            entries.add(populateEntry(PSBT_IN_TAP_KEY_SIG, null, tapKeyPathSignature.encodeToBitcoin()));
        }

        for(Map.Entry<ECKey, Map<KeyDerivation, List<Sha256Hash>>> entry : tapDerivedPublicKeys.entrySet()) {
            if(!entry.getValue().isEmpty()) {
                entries.add(populateEntry(PSBT_IN_TAP_BIP32_DERIVATION, entry.getKey().getPubKeyXCoord(), serializeTaprootKeyDerivation(Collections.emptyList(), entry.getValue().keySet().iterator().next())));
            }
        }

        if(tapInternalKey != null) {
            entries.add(populateEntry(PSBT_IN_TAP_INTERNAL_KEY, null, tapInternalKey.getPubKeyXCoord()));
        }

        return entries;
    }

    void combine(PSBTInput psbtInput) {
        if(psbtInput.nonWitnessUtxo != null) {
            nonWitnessUtxo = psbtInput.nonWitnessUtxo;
        }

        if(psbtInput.witnessUtxo != null) {
            witnessUtxo = psbtInput.witnessUtxo;
        }

        partialSignatures.putAll(psbtInput.partialSignatures);

        if(psbtInput.sigHash != null) {
            sigHash = psbtInput.sigHash;
        }

        if(psbtInput.redeemScript != null) {
            redeemScript = psbtInput.redeemScript;
        }

        if(psbtInput.witnessScript != null) {
            witnessScript = psbtInput.witnessScript;
        }

        derivedPublicKeys.putAll(psbtInput.derivedPublicKeys);

        if(psbtInput.porCommitment != null) {
            porCommitment = psbtInput.porCommitment;
        }

        proprietary.putAll(psbtInput.proprietary);

        if(psbtInput.tapKeyPathSignature != null) {
            tapKeyPathSignature = psbtInput.tapKeyPathSignature;
        }

        tapDerivedPublicKeys.putAll(psbtInput.tapDerivedPublicKeys);

        if(psbtInput.tapInternalKey != null) {
            tapInternalKey = psbtInput.tapInternalKey;
        }
    }

    public Transaction getNonWitnessUtxo() {
        return nonWitnessUtxo;
    }

    public void setNonWitnessUtxo(Transaction nonWitnessUtxo) {
        this.nonWitnessUtxo = nonWitnessUtxo;
    }

    public TransactionOutput getWitnessUtxo() {
        return witnessUtxo;
    }

    public void setWitnessUtxo(TransactionOutput witnessUtxo) {
        this.witnessUtxo = witnessUtxo;
    }

    public TransactionSignature getPartialSignature(ECKey publicKey) {
        return partialSignatures.get(publicKey);
    }

    public SigHash getSigHash() {
        return sigHash;
    }

    public void setSigHash(SigHash sigHash) {
        this.sigHash = sigHash;
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

    public Script getFinalScriptSig() {
        return finalScriptSig;
    }

    public void setFinalScriptSig(Script finalScriptSig) {
        this.finalScriptSig = finalScriptSig;
    }

    public TransactionWitness getFinalScriptWitness() {
        return finalScriptWitness;
    }

    public void setFinalScriptWitness(TransactionWitness finalScriptWitness) {
        this.finalScriptWitness = finalScriptWitness;
    }

    public String getPorCommitment() {
        return porCommitment;
    }

    public void setPorCommitment(String porCommitment) {
        this.porCommitment = porCommitment;
    }

    public Map<ECKey, TransactionSignature> getPartialSignatures() {
        return partialSignatures;
    }

    public ECKey getKeyForSignature(TransactionSignature signature) {
        for(Map.Entry<ECKey, TransactionSignature> entry : partialSignatures.entrySet()) {
            if(entry.getValue().equals(signature)) {
                return entry.getKey();
            }
        }

        return null;
    }

    public Map<ECKey, KeyDerivation> getDerivedPublicKeys() {
        return derivedPublicKeys;
    }

    public Map<String, String> getProprietary() {
        return proprietary;
    }

    public TransactionSignature getTapKeyPathSignature() {
        return tapKeyPathSignature;
    }

    public void setTapKeyPathSignature(TransactionSignature tapKeyPathSignature) {
        this.tapKeyPathSignature = tapKeyPathSignature;
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

    public boolean isTaproot() {
        return getUtxo() != null && getScriptType() == P2TR;
    }

    public boolean isSigned() {
        if(getTapKeyPathSignature() != null) {
            return true;
        } else if(!getPartialSignatures().isEmpty()) {
            try {
                //All partial sigs are already verified
                int reqSigs = getSigningScript().getNumRequiredSignatures();
                int sigs = getPartialSignatures().size();
                return sigs >= reqSigs;
            } catch(NonStandardScriptException e) {
                return false;
            }
        } else {
            return isFinalized();
        }
    }

    public Collection<TransactionSignature> getSignatures() {
        if(getFinalScriptWitness() != null) {
            return getFinalScriptWitness().getSignatures();
        } else if(getFinalScriptSig() != null) {
            return getFinalScriptSig().getSignatures();
        } else if(getTapKeyPathSignature() != null) {
            return List.of(getTapKeyPathSignature());
        } else {
            return getPartialSignatures().values();
        }
    }

    private SigHash getDefaultSigHash() {
        if(isTaproot()) {
            return SigHash.DEFAULT;
        }

        return SigHash.ALL;
    }

    public boolean sign(ECKey privKey) {
        return sign(new PSBTInputSigner() {
            @Override
            public TransactionSignature sign(Sha256Hash hash, SigHash sigHash, TransactionSignature.Type signatureType) {
                return privKey.sign(hash, sigHash, signatureType);
            }

            @Override
            public ECKey getPubKey() {
                return ECKey.fromPublicOnly(privKey);
            }
        });
    }

    public boolean sign(PSBTInputSigner psbtInputSigner) {
        SigHash localSigHash = getSigHash();
        if(localSigHash == null) {
            localSigHash = getDefaultSigHash();
        }

        if(getNonWitnessUtxo() != null || getWitnessUtxo() != null) {
            Script signingScript = getSigningScript();
            if(signingScript != null) {
                Sha256Hash hash = getHashForSignature(signingScript, localSigHash);
                TransactionSignature.Type type = isTaproot() ? SCHNORR : ECDSA;
                TransactionSignature transactionSignature = psbtInputSigner.sign(hash, localSigHash, type);

                if(type == SCHNORR) {
                    tapKeyPathSignature = transactionSignature;
                } else {
                    ECKey pubKey = psbtInputSigner.getPubKey();
                    getPartialSignatures().put(pubKey, transactionSignature);
                }

                return true;
            }
        }

        return false;
    }

    boolean verifySignatures() throws PSBTSignatureException {
        SigHash localSigHash = getSigHash();
        if(localSigHash == null) {
            localSigHash = getDefaultSigHash();
        }

        if(getNonWitnessUtxo() != null || getWitnessUtxo() != null) {
            Script signingScript = getSigningScript();
            if(signingScript != null) {
                Sha256Hash hash = getHashForSignature(signingScript, localSigHash);

                if(isTaproot() && tapKeyPathSignature != null) {
                    ECKey outputKey = P2TR.getPublicKeyFromScript(getUtxo().getScript());
                    if(!outputKey.verify(hash, tapKeyPathSignature)) {
                        throw new PSBTSignatureException("Tweaked internal key does not verify against provided taproot keypath signature");
                    }
                } else {
                    for(ECKey sigPublicKey : getPartialSignatures().keySet()) {
                        TransactionSignature signature = getPartialSignature(sigPublicKey);
                        if(!sigPublicKey.verify(hash, signature)) {
                            throw new PSBTSignatureException("Partial signature does not verify against provided public key");
                        }
                    }
                }

                //TODO: Implement Bitcoin Script engine to verify finalScriptSig and finalScriptWitness

                return true;
            }
        }

        return false;
    }

    public Map<ECKey, TransactionSignature> getSigningKeys(Set<ECKey> availableKeys) {
        Collection<TransactionSignature> signatures = getSignatures();
        Script signingScript = getSigningScript();

        Map<ECKey, TransactionSignature> signingKeys = new LinkedHashMap<>();
        if(signingScript != null) {
            Sha256Hash hash = getHashForSignature(signingScript, getSigHash() == null ? getDefaultSigHash() : getSigHash());

            for(ECKey sigPublicKey : availableKeys) {
                for(TransactionSignature signature : signatures) {
                    if(sigPublicKey.verify(hash, signature)) {
                        signingKeys.put(sigPublicKey, signature);
                    }
                }
            }
        }

        return signingKeys;
    }

    public ScriptType getScriptType() {
        Script signingScript = getUtxo().getScript();

        boolean p2sh = false;
        if(P2SH.isScriptType(signingScript)) {
            p2sh = true;

            if(getRedeemScript() != null) {
                signingScript = getRedeemScript();
            } else if(getFinalScriptSig() != null) {
                signingScript = getFinalScriptSig().getFirstNestedScript();
            } else {
                return null;
            }
        }

        if(P2WPKH.isScriptType(signingScript)) {
            return p2sh ? P2SH_P2WPKH : P2WPKH;
        } else if(P2WSH.isScriptType(signingScript)) {
            return p2sh ? P2SH_P2WSH : P2WSH;
        }

        return ScriptType.getType(signingScript);
    }

    public Script getSigningScript() {
        Script signingScript = getUtxo().getScript();

        if(P2SH.isScriptType(signingScript)) {
            if(getRedeemScript() != null) {
                signingScript = getRedeemScript();
            } else if(getFinalScriptSig() != null) {
                signingScript = getFinalScriptSig().getFirstNestedScript();
            } else {
                return null;
            }
        }

        if(P2WPKH.isScriptType(signingScript)) {
            signingScript = ScriptType.P2PKH.getOutputScript(signingScript.getPubKeyHash());
        } else if(P2WSH.isScriptType(signingScript)) {
            if(getWitnessScript() != null) {
                signingScript = getWitnessScript();
            } else if(getFinalScriptWitness() != null && getFinalScriptWitness().getWitnessScript() != null) {
                return getFinalScriptWitness().getWitnessScript();
            } else {
                return null;
            }
        }

        if(P2TR.isScriptType(signingScript)) {
            //For now, only support keypath spends and just return the ScriptPubKey
            //In future return the script from PSBT_IN_TAP_LEAF_SCRIPT
        }

        return signingScript;
    }

    public boolean isFinalized() {
        return getFinalScriptSig() != null || getFinalScriptWitness() != null;
    }

    public TransactionInput getInput() {
        return transaction.getInputs().get(index);
    }

    public TransactionOutput getUtxo() {
        int vout = (int)getInput().getOutpoint().getIndex();
        return getWitnessUtxo() != null ? getWitnessUtxo() : (getNonWitnessUtxo() != null ?  getNonWitnessUtxo().getOutputs().get(vout) : null);
    }

    void setIndex(int index) {
        this.index = index;
    }

    public void clearNonFinalFields() {
        partialSignatures.clear();
        sigHash = null;
        redeemScript = null;
        witnessScript = null;
        porCommitment = null;
        proprietary.clear();
        tapDerivedPublicKeys.clear();
        tapKeyPathSignature = null;
    }

    private Sha256Hash getHashForSignature(Script connectedScript, SigHash localSigHash) {
        Sha256Hash hash;

        ScriptType scriptType = getScriptType();
        if(scriptType == ScriptType.P2TR) {
            List<TransactionOutput> spentUtxos = psbt.getPsbtInputs().stream().map(PSBTInput::getUtxo).collect(Collectors.toList());
            hash = transaction.hashForTaprootSignature(spentUtxos, index, !P2TR.isScriptType(connectedScript), connectedScript, localSigHash, null);
        } else if(Arrays.asList(WITNESS_TYPES).contains(scriptType)) {
            long prevValue = getUtxo().getValue();
            hash = transaction.hashForWitnessSignature(index, connectedScript, prevValue, localSigHash);
        } else {
            hash = transaction.hashForLegacySignature(index, connectedScript, localSigHash);
        }

        return hash;
    }
}
