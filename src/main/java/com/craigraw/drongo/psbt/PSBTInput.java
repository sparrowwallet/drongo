package com.craigraw.drongo.psbt;

import com.craigraw.drongo.KeyDerivation;
import com.craigraw.drongo.Utils;
import com.craigraw.drongo.crypto.ECKey;
import com.craigraw.drongo.crypto.LazyECPoint;
import com.craigraw.drongo.protocol.Script;
import com.craigraw.drongo.protocol.Transaction;
import com.craigraw.drongo.protocol.TransactionInput;
import com.craigraw.drongo.protocol.TransactionOutput;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.craigraw.drongo.psbt.PSBTEntry.parseKeyDerivation;

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
    private Map<LazyECPoint, byte[]> partialSignatures = new LinkedHashMap<>();
    private Transaction.SigHash sigHash;
    private Script redeemScript;
    private Script witnessScript;
    private Map<LazyECPoint, KeyDerivation> derivedPublicKeys = new LinkedHashMap<>();
    private Script finalScriptSig;
    private Script finalScriptWitness;
    private String porCommitment;
    private Map<String, String> proprietary = new LinkedHashMap<>();

    private static final Logger log = LoggerFactory.getLogger(PSBTInput.class);

    PSBTInput(List<PSBTEntry> inputEntries) {
        for(PSBTEntry entry : inputEntries) {
            switch(entry.getKeyType()) {
                case PSBT_IN_NON_WITNESS_UTXO:
                    entry.checkOneByteKey();
                    Transaction nonWitnessTx = new Transaction(entry.getData());
                    this.nonWitnessUtxo = nonWitnessTx;
                    log.debug("Found input non witness utxo with txid: " + nonWitnessTx.getTxId() + " version " + nonWitnessTx.getVersion() + " size " + nonWitnessTx.getMessageSize() + " locktime " + nonWitnessTx.getLockTime());
                    for(TransactionInput input: nonWitnessTx.getInputs()) {
                        log.debug(" Transaction input references txid: " + input.getOutpoint().getHash() + " vout " + input.getOutpoint().getIndex() + " with script " + input.getScript());
                    }
                    for(TransactionOutput output: nonWitnessTx.getOutputs()) {
                        log.debug(" Transaction output value: " + output.getValue() + " to addresses " + Arrays.asList(output.getScript().getToAddresses()) + " with script hex " + Hex.toHexString(output.getScript().getProgram()) + " to script " + output.getScript());
                    }
                    break;
                case PSBT_IN_WITNESS_UTXO:
                    entry.checkOneByteKey();
                    TransactionOutput witnessTxOutput = new TransactionOutput(null, entry.getData(), 0);
                    this.witnessUtxo = witnessTxOutput;
                    log.debug("Found input witness utxo amount " + witnessTxOutput.getValue() + " script hex " + Hex.toHexString(witnessTxOutput.getScript().getProgram()) + " script " + witnessTxOutput.getScript() + " addresses " + Arrays.asList(witnessTxOutput.getScript().getToAddresses()));
                    break;
                case PSBT_IN_PARTIAL_SIG:
                    entry.checkOneBytePlusPubKey();
                    LazyECPoint sigPublicKey = new LazyECPoint(ECKey.CURVE.getCurve(), entry.getKeyData());
                    this.partialSignatures.put(sigPublicKey, entry.getData());
                    log.debug("Found input partial signature with public key " + sigPublicKey + " signature " + Hex.toHexString(entry.getData()));
                    break;
                case PSBT_IN_SIGHASH_TYPE:
                    entry.checkOneByteKey();
                    long sighashType = Utils.readUint32(entry.getData(), 0);
                    Transaction.SigHash sigHash = Transaction.SigHash.fromInt((int)sighashType);
                    this.sigHash = sigHash;
                    log.debug("Found input sighash_type " + sigHash.toString());
                    break;
                case PSBT_IN_REDEEM_SCRIPT:
                    entry.checkOneByteKey();
                    Script redeemScript = new Script(entry.getData());
                    this.redeemScript = redeemScript;
                    log.debug("Found input redeem script hex " + Hex.toHexString(redeemScript.getProgram()) + " script " + redeemScript);
                    break;
                case PSBT_IN_WITNESS_SCRIPT:
                    entry.checkOneByteKey();
                    Script witnessScript = new Script(entry.getData());
                    this.witnessScript = witnessScript;
                    log.debug("Found input witness script hex " + Hex.toHexString(witnessScript.getProgram()) + " script " + witnessScript);
                    break;
                case PSBT_IN_BIP32_DERIVATION:
                    entry.checkOneBytePlusPubKey();
                    LazyECPoint derivedPublicKey = new LazyECPoint(ECKey.CURVE.getCurve(), entry.getKeyData());
                    KeyDerivation keyDerivation = parseKeyDerivation(entry.getData());
                    this.derivedPublicKeys.put(derivedPublicKey, keyDerivation);
                    log.debug("Found input bip32_derivation with master fingerprint " + keyDerivation.getMasterFingerprint() + " at path " + keyDerivation.getDerivationPath() + " public key " + derivedPublicKey);
                    break;
                case PSBT_IN_FINAL_SCRIPTSIG:
                    entry.checkOneByteKey();
                    Script finalScriptSig = new Script(entry.getData());
                    this.finalScriptSig = finalScriptSig;
                    log.debug("Found input final scriptSig script hex " + Hex.toHexString(finalScriptSig.getProgram()) + " script " + finalScriptSig.toString());
                    break;
                case PSBT_IN_FINAL_SCRIPTWITNESS:
                    entry.checkOneByteKey();
                    Script finalScriptWitness = new Script(entry.getData());
                    this.finalScriptWitness = finalScriptWitness;
                    log.debug("Found input final scriptWitness script hex " + Hex.toHexString(finalScriptWitness.getProgram()) + " script " + finalScriptWitness.toString());
                    break;
                case PSBT_IN_POR_COMMITMENT:
                    entry.checkOneByteKey();
                    String porMessage = new String(entry.getData(), StandardCharsets.UTF_8);
                    this.porCommitment = porMessage;
                    log.debug("Found input POR commitment message " + porMessage);
                    break;
                case PSBT_IN_PROPRIETARY:
                    this.proprietary.put(Hex.toHexString(entry.getKeyData()), Hex.toHexString(entry.getData()));
                    log.debug("Found proprietary input " + Hex.toHexString(entry.getKeyData()) + ": " + Hex.toHexString(entry.getData()));
                    break;
                default:
                    throw new IllegalStateException("PSBT input not recognized key type: " + entry.getKeyType());
            }
        }
    }

    public Transaction getNonWitnessUtxo() {
        return nonWitnessUtxo;
    }

    public TransactionOutput getWitnessUtxo() {
        return witnessUtxo;
    }

    public byte[] getPartialSignature(LazyECPoint publicKey) {
        return partialSignatures.get(publicKey);
    }

    public Transaction.SigHash getSigHash() {
        return sigHash;
    }

    public Script getRedeemScript() {
        return redeemScript;
    }

    public Script getWitnessScript() {
        return witnessScript;
    }

    public KeyDerivation getKeyDerivation(LazyECPoint publicKey) {
        return derivedPublicKeys.get(publicKey);
    }

    public Script getFinalScriptSig() {
        return finalScriptSig;
    }

    public Script getFinalScriptWitness() {
        return finalScriptWitness;
    }

    public String getPorCommitment() {
        return porCommitment;
    }

    public Map<LazyECPoint, byte[]> getPartialSignatures() {
        return partialSignatures;
    }

    public Map<LazyECPoint, KeyDerivation> getDerivedPublicKeys() {
        return derivedPublicKeys;
    }

    public Map<String, String> getProprietary() {
        return proprietary;
    }
}
