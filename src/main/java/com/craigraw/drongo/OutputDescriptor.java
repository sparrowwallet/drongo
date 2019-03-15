package com.craigraw.drongo;

import com.craigraw.drongo.address.Address;
import com.craigraw.drongo.address.P2PKHAddress;
import com.craigraw.drongo.address.P2SHAddress;
import com.craigraw.drongo.address.P2WPKHAddress;
import com.craigraw.drongo.crypto.ChildNumber;
import com.craigraw.drongo.crypto.DeterministicKey;
import com.craigraw.drongo.crypto.ECKey;
import com.craigraw.drongo.crypto.LazyECPoint;
import com.craigraw.drongo.protocol.Base58;
import com.craigraw.drongo.protocol.Script;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OutputDescriptor {
    private static final Logger log = LoggerFactory.getLogger(OutputDescriptor.class);

    private static final int bip32HeaderP2PKHXPub = 0x0488B21E; //The 4 byte header that serializes in base58 to "xpub".
    private static final int bip32HeaderP2PKHYPub = 0x049D7CB2; //The 4 byte header that serializes in base58 to "ypub".
    private static final int bip32HeaderP2WPKHZPub = 0x04B24746; // The 4 byte header that serializes in base58 to "zpub"

    private static final Pattern DESCRIPTOR_PATTERN = Pattern.compile("(.+)\\((\\[[^\\]]+\\])?(xpub[^/\\)]+)(/[/\\d*']+)?\\)\\)?");

    private String script;
    private int parentFingerprint;
    private String keyDerivationPath;
    private DeterministicKey pubKey;
    private String childDerivationPath;
    private ChildNumber pubKeyChildNumber;

    public OutputDescriptor(String script, int parentFingerprint, String keyDerivationPath, DeterministicKey pubKey, String childDerivationPath, ChildNumber pubKeyChildNumber) {
        this.script = script;
        this.parentFingerprint = parentFingerprint;
        this.keyDerivationPath = keyDerivationPath;
        this.pubKey = pubKey;
        this.childDerivationPath = childDerivationPath;
        this.pubKeyChildNumber = pubKeyChildNumber;
    }

    public String getScript() {
        return script;
    }

    public int getParentFingerprint() {
        return parentFingerprint;
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
        return getChildDerivation(new ChildNumber(0, getPubKey().getChildNumber().isHardened()), childDerivationPath, wildCardReplacement);
    }

    public boolean describesMultipleAddresses() {
        return childDerivationPath.endsWith("/*");
    }

    public List<ChildNumber> getReceivingDerivation(int wildCardReplacement) {
        if(describesMultipleAddresses()) {
            if(childDerivationPath.endsWith("0/*")) {
                return getChildDerivation(new ChildNumber(0, getPubKey().getChildNumber().isHardened()), childDerivationPath, wildCardReplacement);
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
                return getChildDerivation(new ChildNumber(0, getPubKey().getChildNumber().isHardened()), childDerivationPath.replace("0/*", "1/*"), wildCardReplacement);
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

    public Address getAddress(DeterministicKey childKey) {
        Address address = null;
        if(script.equals("pkh")) {
            address = new P2PKHAddress(childKey.getPubKeyHash());
        } else if(script.equals("sh(wpkh")) {
            Address p2wpkhAddress = new P2WPKHAddress(childKey.getPubKeyHash());
            Script receivingP2wpkhScript = p2wpkhAddress.getOutputScript();
            address = P2SHAddress.fromProgram(receivingP2wpkhScript.getProgram());
        } else if(script.equals("wpkh")) {
            address = new P2WPKHAddress(childKey.getPubKeyHash());
        } else {
            throw new IllegalStateException("Cannot determine address for script " + script);
        }

        return address;
    }

    // See https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
    public static OutputDescriptor getOutputDescriptor(String descriptor) {
        String script;
        String keyDerivationPath ="";
        String extPubKey = null;
        String childDerivationPath = "/0/*";

        Matcher matcher = DESCRIPTOR_PATTERN.matcher(descriptor);
        if(matcher.matches()) {
            script = matcher.group(1);
            if(matcher.group(2) != null) {
                keyDerivationPath = matcher.group(2);
            }

            extPubKey = matcher.group(3);
            if(matcher.group(4) != null) {
                childDerivationPath = matcher.group(4);
            }
        } else if (descriptor.startsWith("xpub")) {
            extPubKey = descriptor;
            script = "pkh";
        } else if(descriptor.startsWith("ypub")) {
            extPubKey = descriptor;
            script = "sh(wpkh";
        } else if(descriptor.startsWith("zpub")) {
            extPubKey = descriptor;
            script = "wpkh";
        } else {
            throw new IllegalArgumentException("Could not parse output descriptor:" + descriptor);
        }

        byte[] serializedKey = Base58.decodeChecked(extPubKey);
        ByteBuffer buffer = ByteBuffer.wrap(serializedKey);
        int header = buffer.getInt();
        if(!(header == bip32HeaderP2PKHXPub || header == bip32HeaderP2PKHYPub || header == bip32HeaderP2WPKHZPub)) {
            throw new IllegalArgumentException("Unknown header bytes: " + DeterministicKey.toBase58(serializedKey).substring(0, 4));
        }

        int depth = buffer.get() & 0xFF; // convert signed byte to positive int since depth cannot be negative
        final int parentFingerprint = buffer.getInt();
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

        //Remove account level for depth 4 keys
        if(depth == 4 && (descriptor.startsWith("xpub") || descriptor.startsWith("ypub") || descriptor.startsWith("zpub"))) {
            log.warn("Output descriptor describes a public key derived at depth 4; change addresses not available");
            childDerivationPath = "/*";
        }

        byte[] chainCode = new byte[32];
        buffer.get(chainCode);
        byte[] data = new byte[33];
        buffer.get(data);
        if(buffer.hasRemaining()) {
            throw new IllegalArgumentException("Found unexpected data in key");
        }

        DeterministicKey pubKey = new DeterministicKey(path, chainCode, new LazyECPoint(ECKey.CURVE.getCurve(), data), depth, parentFingerprint);
        return new OutputDescriptor(script, parentFingerprint, keyDerivationPath, pubKey, childDerivationPath, childNumber);
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
        builder.append(script);
        builder.append("(");
        builder.append(getExtendedPublicKey());
        builder.append(childDerivationPath);
        builder.append(")");

        if(script.contains("(")){
            builder.append(")");
        }

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

        buffer.putInt(parentFingerprint);

        buffer.putInt(pubKeyChildNumber.i());

        buffer.put(pubKey.getChainCode());
        buffer.put(pubKey.getPubKey());

        return buffer.array();
    }
}
