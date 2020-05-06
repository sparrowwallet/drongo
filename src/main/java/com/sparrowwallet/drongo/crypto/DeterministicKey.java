package com.sparrowwallet.drongo.crypto;


import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Base58;
import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class DeterministicKey extends ECKey {
    private final DeterministicKey parent;
    private final List<ChildNumber> childNumberPath;
    private final int depth;
    private final byte[] parentFingerprint; // 0 if this key is root node of key hierarchy

    /** 32 bytes */
    private final byte[] chainCode;

    /**
     * Constructs a key from its components, including its public key data and possibly-redundant
     * information about its parent key.  Invoked when deserializing, but otherwise not something that
     * you normally should use.
     */
    public DeterministicKey(List<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            LazyECPoint publicAsPoint,
                            int depth,
                            byte[] parentFingerprint) {
        super(null, compressPoint(publicAsPoint));
        if(chainCode.length != 32) {
            throw new IllegalArgumentException("Chaincode not 32 bytes in length");
        }
        this.parent = null;
        this.childNumberPath = childNumberPath;
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.depth = depth;
        this.parentFingerprint = parentFingerprint;
    }

    public DeterministicKey(List<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            LazyECPoint publicAsPoint,
                            DeterministicKey parent) {
        super(null, compressPoint(publicAsPoint));
        if(chainCode.length != 32) {
            throw new IllegalArgumentException("Chaincode not 32 bytes in length");
        }
        this.parent = parent;
        this.childNumberPath = childNumberPath;
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.depth = parent == null ? 0 : parent.depth + 1;
        this.parentFingerprint = (parent != null) ? parent.getFingerprint() : new byte[4];
    }

    public DeterministicKey(List<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            BigInteger priv,
                            DeterministicKey parent) {
        super(priv, ECKey.publicPointFromPrivate(priv), true);
        this.parent = parent;
        this.childNumberPath = childNumberPath;
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.depth = parent == null ? 0 : parent.depth + 1;
        this.parentFingerprint = (parent != null) ? parent.getFingerprint() : new byte[4];
    }

    /**
     * Return this key's depth in the hierarchy, where the root node is at depth zero.
     * This may be different than the number of segments in the path if this key was
     * deserialized without access to its parent.
     */
    public int getDepth() {
        return depth;
    }

    /** Returns the first 32 bits of the result of {@link #getIdentifier()}. */
    public byte[] getFingerprint() {
        return Arrays.copyOfRange(getIdentifier(), 0, 4);
    }

    /**
     * Returns RIPE-MD160(SHA256(pub key bytes)).
     */
    public byte[] getIdentifier() {
        return Utils.sha256hash160(getPubKey());
    }

    /**
     * Returns the path through some DeterministicHierarchy which reaches this keys position in the tree.
     * A path can be written as 0/1/0 which means the first child of the root, the second child of that node, then
     * the first child of that node.
     */
    public List<ChildNumber> getPath() {
        return Collections.unmodifiableList(childNumberPath);
    }

    public DeterministicKey getParent() {
        return parent;
    }

    /** Returns the last element of the path returned by {@link DeterministicKey#getPath()} */
    public ChildNumber getChildNumber() {
        return childNumberPath.size() == 0 ? ChildNumber.ZERO : childNumberPath.get(childNumberPath.size() - 1);
    }

    public byte[] getChainCode() {
        return chainCode;
    }

    public static String toBase58(byte[] ser) {
        return Base58.encode(addChecksum(ser));
    }

    static byte[] addChecksum(byte[] input) {
        int inputLength = input.length;
        byte[] checksummed = new byte[inputLength + 4];
        System.arraycopy(input, 0, checksummed, 0, inputLength);
        byte[] checksum = Sha256Hash.hashTwice(input);
        System.arraycopy(checksum, 0, checksummed, inputLength, 4);
        return checksummed;
    }
}
