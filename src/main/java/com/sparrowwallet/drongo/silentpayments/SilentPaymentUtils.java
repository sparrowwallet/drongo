package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.wallet.MnemonicException;
import com.sparrowwallet.drongo.wallet.WalletNode;
import org.bitcoin.NativeSecp256k1;
import org.bitcoin.NativeSecp256k1Util;
import org.bitcoin.Secp256k1Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.*;

import static com.sparrowwallet.drongo.protocol.ScriptType.P2TR;

public class SilentPaymentUtils {
    private static final Logger log = LoggerFactory.getLogger(SilentPaymentUtils.class);

    private static final List<ScriptType> SCRIPT_TYPES = List.of(ScriptType.P2TR, ScriptType.P2WPKH, ScriptType.P2SH, ScriptType.P2PKH);

    //Alternative generator point on the secp256k1 curve (x-coordinate) generated from the SHA256 hash of "The scalar for this x is unknown"
    private static final byte[] NUMS_H = {
            (byte) 0x50, (byte) 0x92, (byte) 0x9b, (byte) 0x74, (byte) 0xc1, (byte) 0xa0, (byte) 0x49, (byte) 0x54, (byte) 0xb7, (byte) 0x8b, (byte) 0x4b, (byte) 0x60,
            (byte) 0x35, (byte) 0xe9, (byte) 0x7a, (byte) 0x5e, (byte) 0x07, (byte) 0x8a, (byte) 0x5a, (byte) 0x0f, (byte) 0x28, (byte) 0xec, (byte) 0x96, (byte) 0xd5,
            (byte) 0x47, (byte) 0xbf, (byte) 0xee, (byte) 0x9a, (byte) 0xce, (byte) 0x80, (byte) 0x3a, (byte) 0xc0
    };

    public static final String BIP_0352_INPUTS_TAG = "BIP0352/Inputs";
    public static final String BIP_0352_SHARED_SECRET_TAG = "BIP0352/SharedSecret";
    public static final String BIP_0352_LABEL_TAG = "BIP0352/Label";

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

    public static Map<TransactionInput, ECKey> getInputPubKeys(Transaction tx, Map<HashIndex, Script> spentScriptPubKeys) {
        Map<TransactionInput, ECKey> inputKeys = new LinkedHashMap<>();
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
                                    inputKeys.put(input, pubKey);
                                }
                            }
                            break;
                        case P2SH:
                            Script redeemScript = input.getScriptSig().getFirstNestedScript();
                            if(redeemScript != null && ScriptType.P2WPKH.isScriptType(redeemScript)) {
                                if(input.getWitness() != null && input.getWitness().getPushCount() == 2) {
                                    byte[] pubKey = input.getWitness().getPushes().getLast();
                                    if(pubKey != null && pubKey.length == 33) {
                                        inputKeys.put(input, ECKey.fromPublicOnly(pubKey));
                                    }
                                }
                            }
                            break;
                        case P2WPKH:
                            if(input.getWitness() != null && input.getWitness().getPushCount() == 2) {
                                byte[] pubKey = input.getWitness().getPushes().getLast();
                                if(pubKey != null && pubKey.length == 33) {
                                    inputKeys.put(input, ECKey.fromPublicOnly(pubKey));
                                }
                            }
                            break;
                        case P2PKH:
                            byte[] spkHash = ScriptType.P2PKH.getHashFromScript(scriptPubKey);
                            for(ScriptChunk scriptChunk : input.getScriptSig().getChunks()) {
                                if(scriptChunk.isPubKey() && scriptChunk.getData().length == 33 && Arrays.equals(Utils.sha256hash160(scriptChunk.getData()), spkHash)) {
                                    inputKeys.put(input, scriptChunk.getPubKey());
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

        return inputKeys;
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
        return getTweak(tx, spentScriptPubKeys, true);
    }

    public static byte[] getTweak(Transaction tx, Map<HashIndex, Script> spentScriptPubKeys, boolean compressed) {
        if(tx.getOutputs().stream().noneMatch(output -> ScriptType.P2TR.isScriptType(output.getScript()))) {
            return null;
        }

        if(spendsInvalidSegwitOutput(tx, spentScriptPubKeys)) {
            return null;
        }

        Map<TransactionInput, ECKey> inputKeys = getInputPubKeys(tx, spentScriptPubKeys);
        if(inputKeys.isEmpty()) {
            return null;
        }

        if(!Secp256k1Context.isEnabled()) {
            throw new IllegalStateException("libsecp256k1 is not enabled");
        }

        try {
            byte[][] inputPubKeys = new byte[inputKeys.size()][];
            int index = 0;
            for (ECKey key : inputKeys.values()) {
                inputPubKeys[index++] = key.getPubKey(true);
            }
            byte[] combinedPubKey = NativeSecp256k1.pubKeyCombine(inputPubKeys, true);
            byte[] smallestOutpoint = tx.getInputs().stream().map(input -> input.getOutpoint().bitcoinSerialize()).min(new Utils.LexicographicByteArrayComparator()).orElseThrow();

            byte[] inputHash = Utils.taggedHash(BIP_0352_INPUTS_TAG, Utils.concat(smallestOutpoint, combinedPubKey));
            return NativeSecp256k1.pubKeyTweakMul(combinedPubKey, inputHash, compressed);
        } catch(NativeSecp256k1Util.AssertFailException e) {
            log.error("Error computing tweak", e);
        }

        return null;
    }

    /**
     * Computes the output addresses for a list of silent payments by calculating the shared secret
     * between scan keys, spend keys, and the summed private key derived from the provided UTXOs.
     * Updates each silent payment instance with the corresponding address.
     *
     * @param silentPayments the list of silent payments containing silent payment addresses and metadata
     * @param utxos a map of UTXOs (unspent transaction outputs) to wallet nodes, containing information
     *              about inputs used to derive the summed private key
     * @throws InvalidSilentPaymentException if the computed shared secrets or addresses are invalid
     */
    public static Map<ECKey, EcdhShareAndProof> computeOutputAddresses(List<SilentPayment> silentPayments, Map<HashIndex, WalletNode> utxos) throws InvalidSilentPaymentException {
        Map<ECKey, EcdhShareAndProof> scanKeyProofs = new LinkedHashMap<>();
        SecureRandom random = new SecureRandom();
        ECKey summedPrivateKey = getSummedPrivateKey(utxos.values());
        BigInteger inputHash = getInputHash(utxos.keySet(), summedPrivateKey);
        Map<ECKey, List<SilentPayment>> scanKeyGroups = getScanKeyGroups(silentPayments);
        for(Map.Entry<ECKey, List<SilentPayment>> scanKeyGroup : scanKeyGroups.entrySet()) {
            ECKey scanKey = scanKeyGroup.getKey();
            ECKey ecdhShare = scanKey.multiply(summedPrivateKey.getPrivKey(), true);
            SilentPaymentsDLEQProof dleqProof = SilentPaymentsDLEQProof.generate(summedPrivateKey.getPrivKey(), scanKey, random);
            scanKeyProofs.put(scanKey, new EcdhShareAndProof(ecdhShare, dleqProof));
            ECKey sharedSecret = ecdhShare.multiply(inputHash, true);
            int k = 0;
            for(SilentPayment silentPayment : scanKeyGroup.getValue()) {
                BigInteger tk = new BigInteger(1, Utils.taggedHash(BIP_0352_SHARED_SECRET_TAG,
                        Utils.concat(sharedSecret.getPubKey(true), ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(k).array())));
                if(tk.equals(BigInteger.ZERO) || tk.compareTo(ECKey.CURVE.getCurve().getOrder()) >= 0) {
                    throw new InvalidSilentPaymentException("The tk value is invalid for the eligible silent payments inputs");
                }
                ECKey spendKey = silentPayment.getSilentPaymentAddress().getSpendKey();
                ECKey pkm = spendKey.add(ECKey.fromPublicOnly(ECKey.publicPointFromPrivate(tk).getEncoded(true)), true);
                silentPayment.setAddress(P2TR.getAddress(pkm.getPubKeyXCoord()));
                k++;
            }
        }

        return scanKeyProofs;
    }

    /**
     * Validates that the output scripts for silent payment outputs match the expected scripts
     * computed from the ECDH shares. This implements BIP-375 output script verification.
     *
     * @param silentPayments  List of silent payments sending to a common scan key
     * @param ecdhShare       The ECDH share (a * B_scan), either global or summed from per-input
     * @param summedPublicKey The sum of all eligible input public keys
     * @param outpoints       Set of outpoints for eligible inputs
     * @throws InvalidSilentPaymentException if validation fails or scripts don't match
     */
    public static void validateOutputAddresses(List<SilentPayment> silentPayments, ECKey ecdhShare, ECKey summedPublicKey, Set<HashIndex> outpoints) throws InvalidSilentPaymentException {
        BigInteger inputHash = SilentPaymentUtils.getInputHash(outpoints, summedPublicKey);
        Map<ECKey, List<SilentPayment>> scanKeyGroups = SilentPaymentUtils.getScanKeyGroups(silentPayments);
        for(Map.Entry<ECKey, List<SilentPayment>> scanKeyGroup : scanKeyGroups.entrySet()) {
            // Compute shared secret from ECDH share and input hash
            // Instead of: sharedSecret = scanKey.multiply(inputHash).multiply(summedPrivateKey.getPrivKey())
            // We use: sharedSecret = ecdhShare.multiply(inputHash)
            // Because ecdhShare is already (a * B_scan)
            ECKey sharedSecret = ecdhShare.multiply(inputHash);

            int k = 0;
            for(SilentPayment silentPayment : scanKeyGroup.getValue()) {
                BigInteger tk = new BigInteger(1, Utils.taggedHash(SilentPaymentUtils.BIP_0352_SHARED_SECRET_TAG,
                        Utils.concat(sharedSecret.getPubKey(true), ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(k).array())));
                if(tk.equals(BigInteger.ZERO) || tk.compareTo(ECKey.CURVE.getCurve().getOrder()) >= 0) {
                    throw new InvalidSilentPaymentException("The tk value is invalid for the eligible silent payments inputs");
                }
                ECKey spendKey = silentPayment.getSilentPaymentAddress().getSpendKey();
                ECKey pkm = spendKey.add(ECKey.fromPublicOnly(ECKey.publicPointFromPrivate(tk).getEncoded(true)), true);
                Address expectedAddress = ScriptType.P2TR.getAddress(pkm.getPubKeyXCoord());
                if(!silentPayment.getAddress().equals(expectedAddress)) {
                    throw new InvalidSilentPaymentException("Silent payment output address mismatch: expected " + expectedAddress + " but got " + silentPayment.getAddress());
                }
                k++;
            }
        }
    }

    public static Map<ECKey, List<SilentPayment>> getScanKeyGroups(Collection<SilentPayment> silentPayments) {
        Map<ECKey, List<SilentPayment>> scanKeyGroups = new LinkedHashMap<>();
        for(SilentPayment silentPayment : silentPayments) {
            SilentPaymentAddress address = silentPayment.getSilentPaymentAddress();
            List<SilentPayment> scanKeyGroup = scanKeyGroups.computeIfAbsent(address.getScanKey(), _ -> new ArrayList<>());
            scanKeyGroup.add(silentPayment);
        }

        return scanKeyGroups;
    }

    public static BigInteger getInputHash(Set<HashIndex> outpoints, ECKey summedInputKey) throws InvalidSilentPaymentException {
        byte[] smallestOutpoint = getSmallestOutpoint(outpoints);
        byte[] concat = Utils.concat(smallestOutpoint, summedInputKey.getPubKey(true));
        BigInteger inputHash = new BigInteger(1, Utils.taggedHash(BIP_0352_INPUTS_TAG, concat));
        if(inputHash.equals(BigInteger.ZERO) || inputHash.compareTo(ECKey.CURVE.getCurve().getOrder()) >= 0) {
            throw new InvalidSilentPaymentException("The input hash is invalid for the eligible silent payments inputs");
        }

        return inputHash;
    }

    public static ECKey getSummedPrivateKey(Collection<WalletNode> walletNodes) throws InvalidSilentPaymentException {
        ECKey summedPrivateKey = null;
        for(WalletNode walletNode : walletNodes) {
            if(!walletNode.getWallet().canSendSilentPayments()) {
                continue;
            }

            try {
                ECKey privateKey = walletNode.getWallet().getScriptType().getOutputKey(walletNode.getWallet().getKeystores().getFirst().getKey(walletNode));
                if(walletNode.getWallet().getScriptType() == P2TR && !privateKey.getPubKeyPoint().normalize().getYCoord().toBigInteger().mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
                    privateKey = privateKey.negatePrivate();
                }
                if(summedPrivateKey == null) {
                    summedPrivateKey = privateKey;
                } else {
                    summedPrivateKey = summedPrivateKey.addPrivate(privateKey);
                }
            } catch(MnemonicException e) {
                throw new InvalidSilentPaymentException("Invalid wallet mnemonic for sending silent payment", e);
            }
        }

        if(summedPrivateKey == null) {
            throw new InvalidSilentPaymentException("There are no eligible inputs to derive a silent payments shared secret");
        }

        if(summedPrivateKey.getPrivKey().equals(BigInteger.ZERO)) {
            throw new InvalidSilentPaymentException("The summed private key is zero for the eligible silent payments inputs");
        }

        return summedPrivateKey;
    }

    public static ECKey getSummedPublicKey(Collection<ECKey> publicKeys) {
        ECKey summedKey = null;

        for(ECKey publicKey : publicKeys) {
            if(publicKey != null) {
                if(summedKey == null) {
                    summedKey = publicKey;
                } else {
                    summedKey = summedKey.add(publicKey, true);
                }
            }
        }

        return summedKey;
    }

    public static byte[] getSmallestOutpoint(Set<HashIndex> outpoints) {
        return outpoints.stream().map(outpoint -> new TransactionOutPoint(outpoint.getHash(), outpoint.getIndex())).map(TransactionOutPoint::bitcoinSerialize)
                .min(new Utils.LexicographicByteArrayComparator()).orElseThrow(() -> new IllegalArgumentException("No inputs provided to calculate silent payments input hash"));
    }

    public static ECKey getLabelledSpendKey(ECKey scanPrivateKey, ECKey spendPublicKey, int labelIndex) {
        return spendPublicKey.add(getLabelledTweakKey(scanPrivateKey, labelIndex), true);
    }

    public static ECKey getLabelledTweakKey(ECKey scanPrivateKey, int labelIndex) {
        BigInteger labelTweak = new BigInteger(1, Utils.taggedHash(BIP_0352_LABEL_TAG,
                Utils.concat(scanPrivateKey.getPrivKeyBytes(), ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(labelIndex).array())));
        return ECKey.fromPublicOnly(ECKey.publicPointFromPrivate(labelTweak).getEncoded(true));
    }

    public static byte[] getSecp256k1PubKey(ECKey ecKey) {
        return getSecp256k1PubKey(ecKey.getPubKey(false));
    }

    public static byte[] getSecp256k1PubKey(byte[] uncompressedKey) {
        byte[] key = new byte[64];
        System.arraycopy(uncompressedKey, 1, key, 32, 32);
        System.arraycopy(uncompressedKey, 33, key, 0, 32);
        return Utils.reverseBytes(key);
    }

    public record EcdhShareAndProof(ECKey ecdhShare, SilentPaymentsDLEQProof dleqProof) {}
}
