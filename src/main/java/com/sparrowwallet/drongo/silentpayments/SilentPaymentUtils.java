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
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class SilentPaymentUtils {
    private static final Logger log = LoggerFactory.getLogger(SilentPaymentUtils.class);

    private static final List<ScriptType> SCRIPT_TYPES = List.of(ScriptType.P2TR, ScriptType.P2WPKH, ScriptType.P2SH, ScriptType.P2PKH);

    //Alternative generator point on the secp256k1 curve (x-coordinate) generated from the SHA256 hash of "The scalar for this x is unknown"
    private static final byte[] NUMS_H = {
            (byte) 0x50, (byte) 0x92, (byte) 0x9b, (byte) 0x74, (byte) 0xc1, (byte) 0xa0, (byte) 0x49, (byte) 0x54, (byte) 0xb7, (byte) 0x8b, (byte) 0x4b, (byte) 0x60,
            (byte) 0x35, (byte) 0xe9, (byte) 0x7a, (byte) 0x5e, (byte) 0x07, (byte) 0x8a, (byte) 0x5a, (byte) 0x0f, (byte) 0x28, (byte) 0xec, (byte) 0x96, (byte) 0xd5,
            (byte) 0x47, (byte) 0xbf, (byte) 0xee, (byte) 0x9a, (byte) 0xce, (byte) 0x80, (byte) 0x3a, (byte) 0xc0
    };

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
                            if(input.getWitness() != null && input.getWitness().getPushCount() >= 1) {
                                List<byte[]> stack = input.getWitness().getPushes();
                                if(stack.size() > 1 && stack.getLast().length > 0 && stack.getLast()[0] == 0x50) {  //Last item is annex
                                    stack = stack.subList(0, stack.size() - 1);
                                }

                                if(stack.size() > 1) {
                                    // Script path spend
                                    byte[] controlBlock = stack.getLast();
                                    // Control block is <control byte> <32 byte internal key> and 0 or more <32 byte hash>
                                    if(controlBlock.length >= 33) {
                                        byte[] internalKey = Arrays.copyOfRange(controlBlock, 1, 33);
                                        if(Arrays.equals(internalKey, NUMS_H)) {
                                            break;
                                        }
                                    }
                                }

                                ECKey pubKey = ScriptType.P2TR.getPublicKeyFromScript(scriptPubKey);
                                if(pubKey.isCompressed()) {
                                    keys.add(pubKey);
                                }
                            }
                            break;
                        case P2SH:
                            Script redeemScript = input.getScriptSig().getFirstNestedScript();
                            if(ScriptType.P2WPKH.isScriptType(redeemScript)) {
                                if(input.getWitness() != null && input.getWitness().getPushCount() == 2) {
                                    byte[] pubKey = input.getWitness().getPushes().getLast();
                                    if(pubKey != null && pubKey.length == 33) {
                                        keys.add(ECKey.fromPublicOnly(pubKey));
                                    }
                                }
                            }
                            break;
                        case P2WPKH:
                            if(input.getWitness() != null && input.getWitness().getPushCount() == 2) {
                                byte[] pubKey = input.getWitness().getPushes().getLast();
                                if(pubKey != null && pubKey.length == 33) {
                                    keys.add(ECKey.fromPublicOnly(pubKey));
                                }
                            }
                            break;
                        case P2PKH:
                            byte[] spkHash = ScriptType.P2PKH.getHashFromScript(scriptPubKey);
                            for(ScriptChunk scriptChunk : input.getScriptSig().getChunks()) {
                                if(scriptChunk.isPubKey() && scriptChunk.getData().length == 33 && Arrays.equals(Utils.sha256hash160(scriptChunk.getData()), spkHash)) {
                                    keys.add(scriptChunk.getPubKey());
                                    break;
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
