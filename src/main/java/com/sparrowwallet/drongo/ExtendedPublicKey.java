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

    private KeyDerivation keyDerivation;
    private byte[] parentFingerprint;
    private DeterministicKey pubKey;
    private String childDerivationPath;
    private ChildNumber pubKeyChildNumber;

    private DeterministicHierarchy hierarchy;

    public ExtendedPublicKey(String masterFingerprint, byte[] parentFingerprint, String keyDerivationPath, DeterministicKey pubKey, String childDerivationPath, ChildNumber pubKeyChildNumber) {
        this.keyDerivation = new KeyDerivation(masterFingerprint, keyDerivationPath);
        this.parentFingerprint = parentFingerprint;
        this.pubKey = pubKey;
        this.childDerivationPath = childDerivationPath;
        this.pubKeyChildNumber = pubKeyChildNumber;

        this.hierarchy = new DeterministicHierarchy(pubKey);
    }

    public String getMasterFingerprint() {
        return keyDerivation.getMasterFingerprint();
    }

    public byte[] getParentFingerprint() {
        return parentFingerprint;
    }

    public byte[] getFingerprint() {
        return pubKey.getFingerprint();
    }

    public String getKeyDerivationPath() {
        return keyDerivation.getDerivationPath();
    }

    public List<ChildNumber> getKeyDerivation() {
        return keyDerivation.getParsedDerivationPath();
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

    public static ExtendedPublicKey fromDescriptor(String masterFingerprint, String keyDerivationPath, String extPubKey, String childDerivationPath) {
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
        path = Collections.unmodifiableList(new ArrayList<>(Arrays.asList(childNumber)));

        byte[] chainCode = new byte[32];
        buffer.get(chainCode);
        byte[] data = new byte[33];
        buffer.get(data);
        if(buffer.hasRemaining()) {
            throw new IllegalArgumentException("Found unexpected data in key");
        }

        if(childDerivationPath == null) {
            childDerivationPath = writePath(Collections.singletonList(childNumber));
        }

        DeterministicKey pubKey = new DeterministicKey(path, chainCode, new LazyECPoint(ECKey.CURVE.getCurve(), data), depth, parentFingerprint);
        return new ExtendedPublicKey(masterFingerprint, parentFingerprint, keyDerivationPath, pubKey, childDerivationPath, childNumber);
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
