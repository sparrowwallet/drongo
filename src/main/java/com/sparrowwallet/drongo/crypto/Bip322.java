package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTInputSigner;
import com.sparrowwallet.drongo.psbt.PSBTSignatureException;

import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.*;

import static com.sparrowwallet.drongo.protocol.ScriptType.P2TR;

public class Bip322 {
    public static String signMessageBip322(ScriptType scriptType, Address address, String message, PSBTInputSigner psbtInputSigner) {
        checkScriptType(scriptType);

        Transaction toSpend = getBip322ToSpend(address, message);
        Transaction toSign = getBip322ToSign(toSpend);

        TransactionOutput utxoOutput = toSpend.getOutputs().get(0);

        PSBT psbt = new PSBT(toSign);
        PSBTInput psbtInput = psbt.getPsbtInputs().get(0);
        psbtInput.setWitnessUtxo(utxoOutput);
        psbtInput.setSigHash(SigHash.ALL);
        psbtInput.sign(psbtInputSigner);

        ECKey pubKey = psbtInputSigner.getPubKey();
        TransactionSignature signature = psbtInput.isTaproot() ? psbtInput.getTapKeyPathSignature() : psbtInput.getPartialSignature(pubKey);

        Transaction finalizeTransaction = new Transaction();
        TransactionInput finalizedTxInput = scriptType.addSpendingInput(finalizeTransaction, utxoOutput, pubKey, signature);

        return Base64.getEncoder().encodeToString(finalizedTxInput.getWitness().toByteArray());
    }

    public static void verifyMessageBip322(ScriptType scriptType, Address address, String message, String signatureBase64) throws SignatureException {
        checkScriptType(scriptType);

        byte[] signatureEncoded;
        try {
            signatureEncoded = Base64.getDecoder().decode(signatureBase64);
        } catch(IllegalArgumentException e) {
            throw new SignatureException("Could not decode base64 signature", e);
        }

        TransactionWitness witness = new TransactionWitness(null, signatureEncoded, 0);
        TransactionSignature signature;
        ECKey pubKey;

        if(address.getScriptType() == ScriptType.P2WPKH) {
            signature = witness.getSignatures().get(0);
            pubKey = ECKey.fromPublicOnly(witness.getPushes().get(1));

            if(!address.equals(scriptType.getAddress(pubKey))) {
                throw new SignatureException("Provided address does not match pubkey in signature");
            }
        } else if(scriptType == ScriptType.P2TR) {
            signature = witness.getSignatures().get(0);
            pubKey = P2TR.getPublicKeyFromScript(address.getOutputScript());
        } else {
            throw new IllegalArgumentException(scriptType + " addresses are not supported");
        }

        Transaction toSpend = getBip322ToSpend(address, message);
        Transaction toSign = getBip322ToSign(toSpend);

        PSBT psbt = new PSBT(toSign);
        PSBTInput psbtInput = psbt.getPsbtInputs().get(0);
        psbtInput.setWitnessUtxo(toSpend.getOutputs().get(0));
        psbtInput.setSigHash(SigHash.ALL);

        if(scriptType == ScriptType.P2TR) {
            psbtInput.setTapKeyPathSignature(signature);
        } else {
            psbtInput.getPartialSignatures().put(pubKey, signature);
        }

        try {
            psbt.verifySignatures();
        } catch(PSBTSignatureException e) {
            throw new SignatureException("Signature did not match for message", e);
        }
    }

    private static void checkScriptType(ScriptType scriptType) {
        if(!scriptType.isAllowed(PolicyType.SINGLE)) {
            throw new UnsupportedOperationException("Only singlesig addresses are currently supported");
        }

        if(!Arrays.asList(ScriptType.WITNESS_TYPES).contains(scriptType)) {
            throw new UnsupportedOperationException("Legacy addresses are not supported for BIP322 simple signatures");
        }

        if(scriptType == ScriptType.P2SH_P2WPKH) {
            throw new UnsupportedOperationException("The P2SH-P2WPKH script type is not currently supported");
        }
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
        toSpend.getInputs().get(0).setSequenceNumber(0L);
        toSpend.addOutput(0L, address.getOutputScript());

        return toSpend;
    }

    public static Transaction getBip322ToSign(Transaction toSpend) {
        Transaction toSign = new Transaction();
        toSign.setVersion(0);
        toSign.setLocktime(0);

        TransactionWitness witness = new TransactionWitness(toSign);
        toSign.addInput(toSpend.getTxId(), 0L, new Script(new byte[0]), witness);
        toSign.getInputs().get(0).setSequenceNumber(0L);
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
