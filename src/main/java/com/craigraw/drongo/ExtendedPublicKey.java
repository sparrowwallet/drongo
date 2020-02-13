package com.craigraw.drongo;

import com.craigraw.drongo.crypto.*;
import com.craigraw.drongo.protocol.Base58;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class ExtendedPublicKey {
    private static final int bip32HeaderP2PKHXPub = 0x0488B21E; //The 4 byte header that serializes in base58 to "xpub".
    private static final int bip32HeaderP2PKHYPub = 0x049D7CB2; //The 4 byte header that serializes in base58 to "ypub".
    private static final int bip32HeaderP2WPKHZPub = 0x04B24746; // The 4 byte header that serializes in base58 to "zpub"
    private static final int bip32HeaderP2WHSHPub = 0x2AA7ED3; // The 4 byte header that serializes in base58 to "Zpub"

    private byte[] parentFingerprint;
    private String keyDerivationPath;
    private DeterministicKey pubKey;
    private String childDerivationPath;
    private ChildNumber pubKeyChildNumber;

    private DeterministicHierarchy hierarchy;

    public ExtendedPublicKey(byte[] parentFingerprint, String keyDerivationPath, DeterministicKey pubKey, String childDerivationPath, ChildNumber pubKeyChildNumber) {
        this.parentFingerprint = parentFingerprint;
        this.keyDerivationPath = keyDerivationPath;
        this.pubKey = pubKey;
        this.childDerivationPath = childDerivationPath;
        this.pubKeyChildNumber = pubKeyChildNumber;

        this.hierarchy = new DeterministicHierarchy(pubKey);
    }

    public byte[] getParentFingerprint() {
        return parentFingerprint;
    }

    public byte[] getFingerprint() {
        return pubKey.getFingerprint();
    }

    public List<ChildNumber> getKeyDerivation() {
        return parsePath(keyDerivationPath);
    }

    public DeterministicKey getPubKey() {
        return pubKey;
    }

    public List<ChildNumber> getChildDerivation() {
        return getChildDerivation(0);
    }

    public List<ChildNumber> getChildDerivation(int wildCardReplacement) {
        return getChildDerivation(getPubKey().getChildNumber(), childDerivationPath, wildCardReplacement);
    }

    public boolean describesMultipleAddresses() {
        return childDerivationPath.endsWith("/*");
    }

    public List<ChildNumber> getReceivingDerivation(int wildCardReplacement) {
        if(describesMultipleAddresses()) {
            if(childDerivationPath.endsWith("0/*")) {
                return getChildDerivation(getPubKey().getChildNumber(), childDerivationPath, wildCardReplacement);
            }

            if(pubKeyChildNumber.num() == 0 && childDerivationPath.endsWith("/*")) {
                return getChildDerivation(new ChildNumber(0, getPubKey().getChildNumber().isHardened()), childDerivationPath, wildCardReplacement);
            }
        }

        throw new IllegalStateException("Cannot derive receiving address from output descriptor " + this.toString());
    }

    public List<ChildNumber> getChangeDerivation(int wildCardReplacement) {
        if(describesMultipleAddresses()) {
            if(childDerivationPath.endsWith("0/*")) {
                return getChildDerivation(getPubKey().getChildNumber(), childDerivationPath.replace("0/*", "1/*"), wildCardReplacement);
            }

            if(pubKeyChildNumber.num() == 1 && childDerivationPath.endsWith("/*")) {
                return getChildDerivation(new ChildNumber(1, getPubKey().getChildNumber().isHardened()), childDerivationPath, wildCardReplacement);
            }
        }

        throw new IllegalStateException("Cannot derive change address from output descriptor " + this.toString());
    }

    private List<ChildNumber> getChildDerivation(ChildNumber firstChild, String derivationPath, int wildCardReplacement) {
        List<ChildNumber> path = new ArrayList<>();
        path.add(firstChild);
        path.addAll(parsePath(derivationPath, wildCardReplacement));

        return path;
    }

    public DeterministicKey getKey(List<ChildNumber> path) {
        return hierarchy.get(path);
    }

    public static List<ChildNumber> parsePath(String path) {
        return parsePath(path, 0);
    }

    public static List<ChildNumber> parsePath(String path, int wildcardReplacement) {
        String[] parsedNodes = path.replace("M", "").split("/");
        List<ChildNumber> nodes = new ArrayList<>();

        for (String n : parsedNodes) {
            n = n.replaceAll(" ", "");
            if (n.length() == 0) continue;
            boolean isHard = n.endsWith("H") || n.endsWith("h") || n.endsWith("'");
            if (isHard) n = n.substring(0, n.length() - 1);
            if (n.equals("*")) n = Integer.toString(wildcardReplacement);
            int nodeNumber = Integer.parseInt(n);
            nodes.add(new ChildNumber(nodeNumber, isHard));
        }

        return nodes;
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(getExtendedPublicKey());
        builder.append(childDerivationPath);
        return builder.toString();
    }

    public String getExtendedPublicKey() {
        return Base58.encodeChecked(getExtendedPublicKeyBytes());
    }

    public byte[] getExtendedPublicKeyBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(78);
        buffer.putInt(bip32HeaderP2PKHXPub);

        List<ChildNumber> childPath = parsePath(childDerivationPath);
        int depth = 5 - childPath.size();
        buffer.put((byte)depth);

        buffer.put(parentFingerprint);

        buffer.putInt(pubKeyChildNumber.i());

        buffer.put(pubKey.getChainCode());
        buffer.put(pubKey.getPubKey());

        return buffer.array();
    }

    static ExtendedPublicKey fromDescriptor(String keyDerivationPath, String extPubKey, String childDerivationPath) {
        byte[] serializedKey = Base58.decodeChecked(extPubKey);
        ByteBuffer buffer = ByteBuffer.wrap(serializedKey);
        int header = buffer.getInt();
        if(!(header == bip32HeaderP2PKHXPub || header == bip32HeaderP2PKHYPub || header == bip32HeaderP2WPKHZPub || header == bip32HeaderP2WHSHPub)) {
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
        path = Collections.unmodifiableList(new ArrayList<>(Arrays.asList(childNumber)));

        byte[] chainCode = new byte[32];
        buffer.get(chainCode);
        byte[] data = new byte[33];
        buffer.get(data);
        if(buffer.hasRemaining()) {
            throw new IllegalArgumentException("Found unexpected data in key");
        }

        DeterministicKey pubKey = new DeterministicKey(path, chainCode, new LazyECPoint(ECKey.CURVE.getCurve(), data), depth, parentFingerprint);
        return new ExtendedPublicKey(parentFingerprint, keyDerivationPath, pubKey, childDerivationPath, childNumber);
    }
}
