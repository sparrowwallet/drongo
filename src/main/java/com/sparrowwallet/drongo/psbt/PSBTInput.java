package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.sparrowwallet.drongo.protocol.ScriptType.*;
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

    private final Transaction transaction;
    private final int index;

    private static final Logger log = LoggerFactory.getLogger(PSBTInput.class);

    PSBTInput(Transaction transaction, int index) {
        this.transaction = transaction;
        this.index = index;
    }

    PSBTInput(ScriptType scriptType, Transaction transaction, int index, Transaction utxo, int utxoIndex, Script redeemScript, Script witnessScript, Map<ECKey, KeyDerivation> derivedPublicKeys, Map<String, String> proprietary, boolean alwaysAddNonWitnessTx) {
        this(transaction, index);
        sigHash = SigHash.ALL;

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

        this.derivedPublicKeys.putAll(derivedPublicKeys);
        this.proprietary.putAll(proprietary);
    }

    PSBTInput(List<PSBTEntry> inputEntries, Transaction transaction, int index) throws PSBTParseException {
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
                        try {
                            log.debug(" Transaction output value: " + output.getValue() + " to addresses " + Arrays.asList(output.getScript().getToAddresses()) + " with script hex " + Utils.bytesToHex(output.getScript().getProgram()) + " to script " + output.getScript());
                        } catch(NonStandardScriptException e) {
                            log.error("Unknown script type", e);
                        }
                    }
                    break;
                case PSBT_IN_WITNESS_UTXO:
                    entry.checkOneByteKey();
                    TransactionOutput witnessTxOutput = new TransactionOutput(null, entry.getData(), 0);
                    if(!P2SH.isScriptType(witnessTxOutput.getScript()) && !P2WPKH.isScriptType(witnessTxOutput.getScript()) && !P2WSH.isScriptType(witnessTxOutput.getScript())) {
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
                    //TODO: Verify signature
                    TransactionSignature signature = TransactionSignature.decodeFromBitcoin(entry.getData(), true, false);
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
                    if(scriptPubKey == null || !P2SH.isScriptType(scriptPubKey)) {
                        throw new PSBTParseException("PSBT provided a redeem script for a transaction output that does not need one");
                    }
                    if(!Arrays.equals(Utils.sha256hash160(redeemScript.getProgram()), scriptPubKey.getPubKeyHash())) {
                        throw new PSBTParseException("Redeem script hash does not match transaction output script pubkey hash " + Utils.bytesToHex(scriptPubKey.getPubKeyHash()));
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
                        throw new PSBTParseException("Witness script provided without P2WSH witness utxo or P2SH redeem script");
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
            entries.add(populateEntry(PSBT_IN_NON_WITNESS_UTXO, null, nonWitnessUtxo.bitcoinSerialize()));
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

    public boolean isSigned() {
        if(!getPartialSignatures().isEmpty()) {
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
        } else {
            return getPartialSignatures().values();
        }
    }

    public boolean sign(ECKey privKey) {
        SigHash localSigHash = getSigHash();
        if(localSigHash == null) {
            //Assume SigHash.ALL
            localSigHash = SigHash.ALL;
        }

        if(getNonWitnessUtxo() != null || getWitnessUtxo() != null) {
            Script signingScript = getSigningScript();
            if(signingScript != null) {
                Sha256Hash hash = getHashForSignature(signingScript, localSigHash);
                ECKey.ECDSASignature ecdsaSignature = privKey.sign(hash);
                TransactionSignature transactionSignature = new TransactionSignature(ecdsaSignature, localSigHash);

                ECKey pubKey = ECKey.fromPublicOnly(privKey);
                getPartialSignatures().put(pubKey, transactionSignature);

                return true;
            }
        }

        return false;
    }

    boolean verifySignatures() throws PSBTParseException {
        SigHash localSigHash = getSigHash();
        if(localSigHash == null) {
            //Assume SigHash.ALL
            localSigHash = SigHash.ALL;
        }

        if(getNonWitnessUtxo() != null || getWitnessUtxo() != null) {
            Script signingScript = getSigningScript();
            if(signingScript != null) {
                Sha256Hash hash = getHashForSignature(signingScript, localSigHash);

                for(ECKey sigPublicKey : getPartialSignatures().keySet()) {
                    TransactionSignature signature = getPartialSignature(sigPublicKey);
                    if(!sigPublicKey.verify(hash, signature)) {
                        throw new PSBTParseException("Partial signature does not verify against provided public key");
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
            Sha256Hash hash = getHashForSignature(signingScript, getSigHash() == null ? SigHash.ALL : getSigHash());

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

        return signingScript;
    }

    public boolean isFinalized() {
        return getFinalScriptSig() != null || getFinalScriptWitness() != null;
    }

    public TransactionInput getInput() {
        return transaction.getInputs().get(index);
    }

    public TransactionOutput getUtxo() {
        int vout = (int)transaction.getInputs().get(index).getOutpoint().getIndex();
        return getWitnessUtxo() != null ? getWitnessUtxo() : (getNonWitnessUtxo() != null ?  getNonWitnessUtxo().getOutputs().get(vout) : null);
    }

    public void clearNonFinalFields() {
        partialSignatures.clear();
        sigHash = null;
        redeemScript = null;
        witnessScript = null;
        porCommitment = null;
        proprietary.clear();
    }

    private Sha256Hash getHashForSignature(Script connectedScript, SigHash localSigHash) {
        Sha256Hash hash;

        ScriptType scriptType = getScriptType();
        if(Arrays.asList(WITNESS_TYPES).contains(scriptType)) {
            long prevValue = getUtxo().getValue();
            hash = transaction.hashForWitnessSignature(index, connectedScript, prevValue, localSigHash);
        } else {
            hash = transaction.hashForLegacySignature(index, connectedScript, localSigHash);
        }

        return hash;
    }
}
