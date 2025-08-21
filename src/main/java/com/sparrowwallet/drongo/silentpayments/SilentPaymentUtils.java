package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import org.bitcoin.NativeSecp256k1;
import org.bitcoin.NativeSecp256k1Util;
import org.bitcoin.Secp256k1Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class SilentPaymentUtils {
    private static final Logger log = LoggerFactory.getLogger(SilentPaymentUtils.class);

    private static final List<ScriptType> SCRIPT_TYPES = List.of(ScriptType.P2TR, ScriptType.P2WPKH, ScriptType.P2SH_P2WPKH, ScriptType.P2PKH);

    public static boolean isEligible(Transaction tx, Map<HashIndex, Script> spentScriptPubKeys) {
        if(!containsTaprootOutput(tx)) {
            return false;
        }

        if(getInputPubKeys(tx, spentScriptPubKeys).isEmpty()) {
            return false;
        }

        if(spendsInvalidSegwitOutput(tx, spentScriptPubKeys)) {
            return false;
        }

        return true;
    }

    public static List<ECKey> getInputPubKeys(Transaction tx, Map<HashIndex, Script> spentScriptPubKeys) {
        List<ECKey> keys = new ArrayList<>();
        for(TransactionInput input : tx.getInputs()) {
            HashIndex hashIndex = new HashIndex(input.getOutpoint().getHash(), input.getOutpoint().getIndex());
            Script scriptPubKey = spentScriptPubKeys.get(hashIndex);
            if(scriptPubKey == null) {
                throw new IllegalStateException("No scriptPubKey found for input " + input.getOutpoint().getHash() + ":" + input.getOutpoint().getIndex());
            }
            for(ScriptType scriptType : SCRIPT_TYPES) {
                if(scriptType.isScriptType(scriptPubKey)) {
                    switch(scriptType) {
                        case P2TR:
                            keys.add(ScriptType.P2TR.getPublicKeyFromScript(scriptPubKey));
                            break;
                        case P2WPKH:
                        case P2SH_P2WPKH:
                            if(input.getWitness() != null && input.getWitness().getPushCount() == 2) {
                                byte[] pubKey = input.getWitness().getPushes().get(input.getWitness().getPushCount() - 1);
                                if(pubKey != null && pubKey.length == 33) {
                                    keys.add(ECKey.fromPublicOnly(pubKey));
                                }
                            }
                            break;
                        case P2PKH:
                            for(ScriptChunk scriptChunk : input.getScriptSig().getChunks()) {
                                if(scriptChunk.isPubKey() && scriptChunk.getData().length == 33) {
                                    keys.add(scriptChunk.getPubKey());
                                }
                            }
                            break;
                        default:
                            throw new IllegalStateException("Unhandled script type " + scriptType);
                    }
                }
            }
        }

        return keys;
    }

    public static boolean containsTaprootOutput(Transaction tx) {
        for(TransactionOutput output : tx.getOutputs()) {
            if(ScriptType.P2TR.isScriptType(output.getScript())) {
                return true;
            }
        }

        return false;
    }

    public static boolean spendsInvalidSegwitOutput(Transaction tx, Map<HashIndex, Script> spentScriptPubKeys) {
        for(TransactionInput input : tx.getInputs()) {
            HashIndex hashIndex = new HashIndex(input.getOutpoint().getHash(), input.getOutpoint().getIndex());
            Script scriptPubKey = spentScriptPubKeys.get(hashIndex);
            if(scriptPubKey == null) {
                throw new IllegalStateException("No scriptPubKey found for input " + input.getOutpoint().getHash() + ":" + input.getOutpoint().getIndex());
            }
            List<ScriptChunk> chunks = scriptPubKey.getChunks();
            if(chunks.size() == 2 && chunks.getFirst().isOpCode() && chunks.get(1).getData() != null
                    && chunks.getFirst().getOpcode() >= ScriptOpCodes.OP_2 && chunks.getFirst().getOpcode() <= ScriptOpCodes.OP_16) {
                return true;
            }
        }

        return false;
    }

    public static byte[] getTweak(Transaction tx, Map<HashIndex, Script> spentScriptPubKeys) {
        if(tx.getOutputs().stream().noneMatch(output -> ScriptType.P2TR.isScriptType(output.getScript()))) {
            return null;
        }

        if(spendsInvalidSegwitOutput(tx, spentScriptPubKeys)) {
            return null;
        }

        List<ECKey> inputKeys = getInputPubKeys(tx, spentScriptPubKeys);
        if(inputKeys.isEmpty()) {
            return null;
        }

        if(!Secp256k1Context.isEnabled()) {
            throw new IllegalStateException("libsecp256k1 is not enabled");
        }

        try {
            byte[][] inputPubKeys = new byte[inputKeys.size()][];
            for(int i = 0; i < inputPubKeys.length; i++) {
                inputPubKeys[i] = inputKeys.get(i).getPubKey(true);
            }
            byte[] combinedPubKey = NativeSecp256k1.pubKeyCombine(inputPubKeys, true);
            byte[] smallestOutpoint = tx.getInputs().stream().map(input -> input.getOutpoint().bitcoinSerialize()).min(new Utils.LexicographicByteArrayComparator()).orElseThrow();

            byte[] inputHash = Utils.taggedHash("BIP0352/Inputs", Utils.concat(smallestOutpoint, combinedPubKey));
            return NativeSecp256k1.pubKeyTweakMul(combinedPubKey, inputHash, true);
        } catch(NativeSecp256k1Util.AssertFailException e) {
            log.error("Error computing tweak", e);
        }

        return null;
    }
}
