package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.crypto.*;
import com.sparrowwallet.drongo.protocol.Base58;

import java.nio.ByteBuffer;
import java.util.*;

import static com.sparrowwallet.drongo.KeyDerivation.parsePath;
import static com.sparrowwallet.drongo.KeyDerivation.writePath;

public class ExtendedPublicKey {
    private static final int bip32HeaderP2PKHXPub = 0x0488B21E; //The 4 byte header that serializes in base58 to "xpub".
    private static final int bip32HeaderP2PKHYPub = 0x049D7CB2; //The 4 byte header that serializes in base58 to "ypub".
    private static final int bip32HeaderP2WPKHZPub = 0x04B24746; // The 4 byte header that serializes in base58 to "zpub"
    private static final int bip32HeaderP2WHSHPub = 0x2AA7ED3; // The 4 byte header that serializes in base58 to "Zpub"
    private static final int bip32HeaderTestnetPub = 0x43587CF; // The 4 byte header that serializes in base58 to "tpub"

    private final byte[] parentFingerprint;
    private final DeterministicKey pubKey;
    private final ChildNumber pubKeyChildNumber;
    private final DeterministicHierarchy hierarchy;

    public ExtendedPublicKey(DeterministicKey pubKey, byte[] parentFingerprint, ChildNumber pubKeyChildNumber) {
        this.parentFingerprint = parentFingerprint;
        this.pubKey = pubKey;
        this.pubKeyChildNumber = pubKeyChildNumber;
        this.hierarchy = new DeterministicHierarchy(pubKey);
    }

    public byte[] getParentFingerprint() {
        return parentFingerprint;
    }

    public DeterministicKey getPubKey() {
        return pubKey;
    }

    public DeterministicKey getKey(List<ChildNumber> path) {
        return hierarchy.get(path);
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(getExtendedPublicKey());
        return builder.toString();
    }

    public String getExtendedPublicKey() {
        return Base58.encodeChecked(getExtendedPublicKeyBytes());
    }

    public ChildNumber getPubKeyChildNumber() {
        return pubKeyChildNumber;
    }

    public byte[] getExtendedPublicKeyBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(78);
        buffer.putInt(bip32HeaderP2PKHXPub);
        buffer.put((byte)pubKey.getDepth());
        buffer.put(parentFingerprint);
        buffer.putInt(pubKeyChildNumber.i());
        buffer.put(pubKey.getChainCode());
        buffer.put(pubKey.getPubKey());

        return buffer.array();
    }

    public static ExtendedPublicKey fromDescriptor(String extPubKey) {
        byte[] serializedKey = Base58.decodeChecked(extPubKey);
        ByteBuffer buffer = ByteBuffer.wrap(serializedKey);
        int header = buffer.getInt();
        if(!(header == bip32HeaderP2PKHXPub || header == bip32HeaderP2PKHYPub || header == bip32HeaderP2WPKHZPub || header == bip32HeaderP2WHSHPub || header == bip32HeaderTestnetPub)) {
            throw new IllegalArgumentException("Unknown header bytes: " + DeterministicKey.toBase58(serializedKey).substring(0, 4));
        }

        int depth = buffer.get() & 0xFF; // convert signed byte to positive int since depth cannot be negative
        byte[] parentFingerprint = new byte[4];
        buffer.get(parentFingerprint);
        final int i = buffer.getInt();
        ChildNumber childNumber;
        List<ChildNumber> path;

        if(depth == 0) {
            //Poorly formatted extended public key, add first child path element
            childNumber = new ChildNumber(0, false);
        } else if ((i & ChildNumber.HARDENED_BIT) != 0) {
            childNumber = new ChildNumber(i ^ ChildNumber.HARDENED_BIT, true); //already hardened
        } else {
            childNumber = new ChildNumber(i, false);
        }
        path = List.of(childNumber);

        byte[] chainCode = new byte[32];
        buffer.get(chainCode);
        byte[] data = new byte[33];
        buffer.get(data);
        if(buffer.hasRemaining()) {
            throw new IllegalArgumentException("Found unexpected data in key");
        }

        DeterministicKey pubKey = new DeterministicKey(path, chainCode, new LazyECPoint(ECKey.CURVE.getCurve(), data), depth, parentFingerprint);
        return new ExtendedPublicKey(pubKey, parentFingerprint, childNumber);
    }

    public static boolean isValid(String extPubKey) {
        try {
            ExtendedPublicKey.fromDescriptor(extPubKey);
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExtendedPublicKey that = (ExtendedPublicKey) o;
        return that.toString().equals(this.toString());
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }
}
