package com.craigraw.drongo.psbt;

import com.craigraw.drongo.KeyDerivation;
import com.craigraw.drongo.crypto.LazyECPoint;
import com.craigraw.drongo.protocol.Script;
import com.craigraw.drongo.protocol.Transaction;
import com.craigraw.drongo.protocol.TransactionOutput;

import java.util.LinkedHashMap;
import java.util.Map;

public class PSBTInput {
    private Transaction nonWitnessUtxo;
    private TransactionOutput witnessUtxo;
    private Map<LazyECPoint, byte[]> partialSignatures = new LinkedHashMap<>();
    private Transaction.SigHash sigHash;
    private Script redeemScript;
    private Script witnessScript;
    private Map<LazyECPoint, KeyDerivation> derivedPublicKeys = new LinkedHashMap<>();
    private Script finalScriptSig;
    private Script finalScriptWitness;
    private String porCommitment;
    private Map<String, String> proprietary = new LinkedHashMap<>();

    public Transaction getNonWitnessUtxo() {
        return nonWitnessUtxo;
    }

    public void setNonWitnessUtxo(Transaction nonWitnessUtxo) {
        testIfNull(this.nonWitnessUtxo);
        this.nonWitnessUtxo = nonWitnessUtxo;
    }

    public TransactionOutput getWitnessUtxo() {
        return witnessUtxo;
    }

    public void setWitnessUtxo(TransactionOutput witnessUtxo) {
        testIfNull(this.witnessUtxo);
        this.witnessUtxo = witnessUtxo;
    }

    public byte[] getPartialSignature(LazyECPoint publicKey) {
        return partialSignatures.get(publicKey);
    }

    public void addPartialSignature(LazyECPoint publicKey, byte[] partialSignature) {
        if(partialSignatures.containsKey(publicKey)) {
            throw new IllegalStateException("Duplicate public key signature in scope");
        }

        this.partialSignatures.put(publicKey, partialSignature);
    }

    public Transaction.SigHash getSigHash() {
        return sigHash;
    }

    public void setSigHash(Transaction.SigHash sigHash) {
        testIfNull(this.sigHash);
        this.sigHash = sigHash;
    }

    public Script getRedeemScript() {
        return redeemScript;
    }

    public void setRedeemScript(Script redeemScript) {
        testIfNull(this.redeemScript);
        this.redeemScript = redeemScript;
    }

    public Script getWitnessScript() {
        return witnessScript;
    }

    public void setWitnessScript(Script witnessScript) {
        testIfNull(this.witnessScript);
        this.witnessScript = witnessScript;
    }

    public KeyDerivation getKeyDerivation(LazyECPoint publicKey) {
        return derivedPublicKeys.get(publicKey);
    }

    public void addDerivedPublicKey(LazyECPoint publicKey, KeyDerivation derivation) {
        if(derivedPublicKeys.containsKey(publicKey)) {
            throw new IllegalStateException("Duplicate public key in scope");
        }

        this.derivedPublicKeys.put(publicKey, derivation);
    }

    public Script getFinalScriptSig() {
        return finalScriptSig;
    }

    public void setFinalScriptSig(Script finalScriptSig) {
        testIfNull(this.finalScriptSig);
        this.finalScriptSig = finalScriptSig;
    }

    public Script getFinalScriptWitness() {
        return finalScriptWitness;
    }

    public void setFinalScriptWitness(Script finalScriptWitness) {
        testIfNull(this.finalScriptWitness);
        this.finalScriptWitness = finalScriptWitness;
    }

    public String getPorCommitment() {
        return porCommitment;
    }

    public void setPorCommitment(String porCommitment) {
        testIfNull(this.porCommitment);
        this.porCommitment = porCommitment;
    }

    public void addProprietary(String key, String data) {
        proprietary.put(key, data);
    }

    private void testIfNull(Object obj) {
        if(obj != null) {
            throw new IllegalStateException("Duplicate keys in scope");
        }
    }
}
