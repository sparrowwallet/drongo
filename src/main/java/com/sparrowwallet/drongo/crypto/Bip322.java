package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTSignatureException;

import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.*;

import static com.sparrowwallet.drongo.protocol.ScriptType.P2TR;

public class Bip322 {
    public static String signMessageBip322(ScriptType scriptType, String message, ECKey privKey) {
        checkScriptType(scriptType);

        ECKey pubKey = ECKey.fromPublicOnly(privKey);
        Address address = scriptType.getAddress(PolicyType.SINGLE_HD, pubKey);

        PSBT psbt = getBip322Psbt(scriptType, address, message);
        PSBTInput psbtInput = psbt.getPsbtInputs().getFirst();
        psbtInput.sign(scriptType.getOutputKey(PolicyType.SINGLE_HD, privKey));

        return getBip322SignatureFromPsbt(scriptType, psbt, pubKey);
    }

    public static PSBT getBip322Psbt(ScriptType scriptType, Address address, String message) {
        checkScriptType(scriptType);

        Transaction toSpend = getBip322ToSpend(address, message);
        Transaction toSign = getBip322ToSign(toSpend);
        TransactionOutput utxoOutput = toSpend.getOutputs().getFirst();

        PSBT psbt = new PSBT(toSign);
        PSBTInput psbtInput = psbt.getPsbtInputs().getFirst();
        psbtInput.setWitnessUtxo(utxoOutput);
        psbtInput.setSigHash(SigHash.ALL);

        return psbt;
    }

    public static String getBip322SignatureFromPsbt(ScriptType scriptType, PSBT signedPsbt, ECKey pubKey) {
        checkScriptType(scriptType);

        PSBTInput psbtInput = signedPsbt.getPsbtInputs().getFirst();
        TransactionSignature signature = psbtInput.isTaproot() ? psbtInput.getTapKeyPathSignature() : psbtInput.getPartialSignature(pubKey);

        if(signature == null) {
            throw new IllegalArgumentException("PSBT does not contain a signature");
        }

        TransactionOutput utxoOutput = psbtInput.getWitnessUtxo();
        Transaction finalizeTransaction = new Transaction();
        Script scriptSig = scriptType.getScriptSig(PolicyType.SINGLE_HD, utxoOutput.getScript(), pubKey, signature);
        TransactionWitness witness = psbtInput.isTaproot() ? new TransactionWitness(finalizeTransaction, signature) : new TransactionWitness(finalizeTransaction, pubKey, signature);
        TransactionInput finalizedTxInput = finalizeTransaction.addInput(Sha256Hash.ZERO_HASH, 0, scriptSig, witness);

        return Base64.getEncoder().encodeToString(finalizedTxInput.getWitness().toByteArray());
    }

    public static boolean verifyMessageBip322(ScriptType scriptType, Address address, String message, String signatureBase64) throws SignatureException {
        checkScriptType(scriptType);

        if(signatureBase64.trim().isEmpty()) {
            throw new SignatureException("Provided signature is empty.");
        }

        byte[] signatureEncoded;
        try {
            signatureEncoded = Base64.getDecoder().decode(signatureBase64);
        } catch(IllegalArgumentException e) {
            throw new SignatureException("Could not decode base64 signature", e);
        }

        TransactionWitness witness;
        try {
            witness = new TransactionWitness(null, signatureEncoded, 0);
        } catch(Exception e) {
            throw new SignatureException("Provided signature is not a BIP322 simple signature.", e);
        }

        TransactionSignature signature;
        ECKey pubKey;

        if(witness.getWitnessScript() != null) {
            throw new IllegalArgumentException("Multisig signatures are not supported.");
        }

        if(witness.getSignatures().isEmpty()) {
            throw new SignatureException("BIP322 simple signature contains no transaction signatures.");
        }

        if(scriptType == ScriptType.P2WPKH) {
            signature = witness.getSignatures().getFirst();
            if(witness.getPushes().size() <= 1) {
                throw new SignatureException("BIP322 simple signature for P2WPKH script type does not contain a pubkey.");
            }
            pubKey = ECKey.fromPublicOnly(witness.getPushes().get(1));

            if(!address.equals(scriptType.getAddress(PolicyType.SINGLE_HD, pubKey))) {
                throw new SignatureException("Provided address does not match pubkey in signature");
            }
        } else if(scriptType == ScriptType.P2TR) {
            signature = witness.getSignatures().getFirst();
            pubKey = P2TR.getPublicKeyFromScript(address.getOutputScript());
        } else {
            throw new SignatureException(scriptType + " addresses are not supported");
        }

        Transaction toSpend = getBip322ToSpend(address, message);
        Transaction toSign = getBip322ToSign(toSpend);

        PSBT psbt = new PSBT(toSign);
        PSBTInput psbtInput = psbt.getPsbtInputs().getFirst();
        psbtInput.setWitnessUtxo(toSpend.getOutputs().getFirst());
        psbtInput.setSigHash(SigHash.ALL);

        if(scriptType == ScriptType.P2TR) {
            psbtInput.setTapKeyPathSignature(signature);
        } else {
            psbtInput.getPartialSignatures().put(pubKey, signature);
        }

        try {
            psbt.verifySignatures();
        } catch(PSBTSignatureException e) {
            return false;
        }

        return true;
    }

    private static void checkScriptType(ScriptType scriptType) {
        if(!scriptType.isAllowed(PolicyType.SINGLE_HD)) {
            throw new UnsupportedOperationException("Only singlesig addresses are currently supported");
        }

        if(!Arrays.asList(ScriptType.WITNESS_TYPES).contains(scriptType)) {
            throw new UnsupportedOperationException("Legacy addresses are not supported for BIP322 simple signatures");
        }

        if(scriptType == ScriptType.P2SH_P2WPKH) {
            throw new UnsupportedOperationException("The P2SH-P2WPKH script type is not currently supported");
        }
    }

    public static boolean isSupported(ScriptType scriptType) {
        return scriptType == ScriptType.P2WPKH || scriptType == P2TR;
    }

    public static Transaction getBip322ToSpend(Address address, String message) {
        Transaction toSpend = new Transaction();
        toSpend.setVersion(0);
        toSpend.setLocktime(0);

        List<ScriptChunk> scriptSigChunks = new ArrayList<>();
        scriptSigChunks.add(ScriptChunk.fromOpcode(ScriptOpCodes.OP_0));
        scriptSigChunks.add(ScriptChunk.fromData(getBip322MessageHash(message)));
        Script scriptSig = new Script(scriptSigChunks);
        toSpend.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, scriptSig, new TransactionWitness(toSpend, Collections.emptyList()));
        toSpend.getInputs().getFirst().setSequenceNumber(0L);
        toSpend.addOutput(0L, address.getOutputScript());

        return toSpend;
    }

    public static Transaction getBip322ToSign(Transaction toSpend) {
        Transaction toSign = new Transaction();
        toSign.setVersion(0);
        toSign.setLocktime(0);

        TransactionWitness witness = new TransactionWitness(toSign);
        toSign.addInput(toSpend.getTxId(), 0L, new Script(new byte[0]), witness);
        toSign.getInputs().getFirst().setSequenceNumber(0L);
        toSign.addOutput(0, new Script(List.of(ScriptChunk.fromOpcode(ScriptOpCodes.OP_RETURN))));

        return toSign;
    }

    public static byte[] getBip322MessageHash(String message) {
        if(message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }

        return Utils.taggedHash("BIP0322-signed-message", message.getBytes(StandardCharsets.UTF_8));
    }
}
