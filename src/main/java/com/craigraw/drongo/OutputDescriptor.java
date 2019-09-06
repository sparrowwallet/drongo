package com.craigraw.drongo;

import com.craigraw.drongo.address.*;
import com.craigraw.drongo.crypto.ChildNumber;
import com.craigraw.drongo.crypto.DeterministicKey;
import com.craigraw.drongo.protocol.Script;
import com.craigraw.drongo.protocol.ScriptChunk;
import com.craigraw.drongo.protocol.ScriptOpCodes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OutputDescriptor {
    private static final Pattern XPUB_PATTERN = Pattern.compile("(\\[[^\\]]+\\])?(.pub[^/\\)]+)(/[/\\d*']+)?");
    private static final Pattern MULTI_PATTERN = Pattern.compile("multi\\(([\\d+])");

    private String script;
    private int multisigThreshold;
    private List<ExtendedPublicKey> extendedPublicKeys;

    public OutputDescriptor(String script, ExtendedPublicKey extendedPublicKey) {
        this(script, Collections.singletonList(extendedPublicKey));
    }

    public OutputDescriptor(String script, List<ExtendedPublicKey> extendedPublicKeys) {
        this(script, 0, extendedPublicKeys);
    }

    public OutputDescriptor(String script, int multisigThreshold, List<ExtendedPublicKey> extendedPublicKeys) {
        this.script = script;
        this.multisigThreshold = multisigThreshold;
        this.extendedPublicKeys = extendedPublicKeys;
    }

    public List<ExtendedPublicKey> getExtendedPublicKeys() {
        return extendedPublicKeys;
    }

    public boolean isMultisig() {
        return extendedPublicKeys.size() > 1;
    }

    public ExtendedPublicKey getSingletonExtendedPublicKey() {
        if(isMultisig()) {
            throw new IllegalStateException("Output descriptor contains multiple public keys but singleton requested");
        }

        return extendedPublicKeys.get(0);
    }

    public String getScript() {
        return script;
    }

    public boolean describesMultipleAddresses() {
        for(ExtendedPublicKey pubKey : extendedPublicKeys) {
            if(!pubKey.describesMultipleAddresses()) {
                return false;
            }
        }

        return true;
    }

    public List<ChildNumber> getChildDerivation() {
        List<ChildNumber> lastDerivation = null;
        for(ExtendedPublicKey pubKey : extendedPublicKeys) {
            List<ChildNumber> derivation = pubKey.getChildDerivation();
            if(lastDerivation != null && !lastDerivation.subList(1, lastDerivation.size()).equals(derivation.subList(1, derivation.size()))) {
                throw new IllegalStateException("Cannot determine multisig derivation: constituent derivations do not match");
            }
            lastDerivation = derivation;
        }

        return lastDerivation;
    }

    public List<ChildNumber> getReceivingDerivation(int wildCardReplacement) {
        if(isMultisig()) {
            List<ChildNumber> path = new ArrayList<>();
            path.add(new ChildNumber(0));
            path.add(new ChildNumber(wildCardReplacement));
            return path;
        }

        return getSingletonExtendedPublicKey().getReceivingDerivation(wildCardReplacement);
    }

    public List<ChildNumber> getChangeDerivation(int wildCardReplacement) {
        if(isMultisig()) {
            List<ChildNumber> path = new ArrayList<>();
            path.add(new ChildNumber(1));
            path.add(new ChildNumber(wildCardReplacement));
            return path;
        }

        return getSingletonExtendedPublicKey().getChangeDerivation(wildCardReplacement);
    }

    public Address getAddress(List<ChildNumber> path) {
        if(isMultisig()) {
            Script script = getMultisigScript(path);
            return getAddress(script);
        }

        DeterministicKey childKey = getSingletonExtendedPublicKey().getKey(path);
        return getAddress(childKey);
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

    private Address getAddress(Script multisigScript) {
        Address address = null;
        if(script.equals("sh(multi")) {
            address = P2SHAddress.fromProgram(multisigScript.getProgram());
        } else if(script.equals("wsh(multi")) {
            address = P2WSHAddress.fromProgram(multisigScript.getProgram());
        } else {
            throw new IllegalStateException("Cannot determine address for multisig script " + script);
        }

        return address;
    }

    private Script getMultisigScript(List<ChildNumber> path) {
        List<ScriptChunk> chunks = new ArrayList<>();
        chunks.add(new ScriptChunk(Script.encodeToOpN(multisigThreshold), null));

        for(ExtendedPublicKey pubKey : extendedPublicKeys) {
            List<ChildNumber> keyPath = null;
            if(path.get(0).num() == 0) {
                keyPath = pubKey.getReceivingDerivation(path.get(1).num());
            } else if(path.get(0).num() == 1) {
                keyPath = pubKey.getChangeDerivation(path.get(1).num());
            } else {
                keyPath = pubKey.getChildDerivation(path.get(1).num());
            }

            byte[] pubKeyBytes = pubKey.getKey(keyPath).getPubKey();
            chunks.add(new ScriptChunk(pubKeyBytes.length, pubKeyBytes));
        }

        chunks.add(new ScriptChunk(Script.encodeToOpN(extendedPublicKeys.size()), null));
        chunks.add(new ScriptChunk(ScriptOpCodes.OP_CHECKMULTISIG, null));

        return new Script(chunks);
    }

    // See https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
    public static OutputDescriptor getOutputDescriptor(String descriptor) {
        if(descriptor.startsWith("pkh") || descriptor.startsWith("xpub")) {
            return new OutputDescriptor("pkh", getExtendedPublicKeys(descriptor));
        } else if(descriptor.startsWith("wpkh") || descriptor.startsWith("zpub")) {
            return new OutputDescriptor("wpkh", getExtendedPublicKeys(descriptor));
        } else if(descriptor.startsWith("sh(wpkh") || descriptor.startsWith("ypub")) {
            return new OutputDescriptor("sh(wpkh", getExtendedPublicKeys(descriptor));
        } else if(descriptor.startsWith("sh(multi") || descriptor.startsWith("Ypub")) {
            return new OutputDescriptor("sh(multi", getMultsigThreshold(descriptor), getExtendedPublicKeys(descriptor));
        } else if(descriptor.startsWith("wsh(multi") || descriptor.startsWith("Zpub")) {
            return new OutputDescriptor("wsh(multi", getMultsigThreshold(descriptor), getExtendedPublicKeys(descriptor));
        } else {
            throw new IllegalArgumentException("Could not parse output descriptor:" + descriptor);
        }
    }

    private static int getMultsigThreshold(String descriptor) {
        Matcher matcher = MULTI_PATTERN.matcher(descriptor);
        if(matcher.find()) {
            String threshold = matcher.group(1);
            return Integer.parseInt(threshold);
        } else {
            throw new IllegalArgumentException("Could not find multisig threshold in output descriptor:" + descriptor);
        }
    }

    private static List<ExtendedPublicKey> getExtendedPublicKeys(String descriptor) {
        List<ExtendedPublicKey> keys = new ArrayList<>();
        Matcher matcher = XPUB_PATTERN.matcher(descriptor);
        while(matcher.find()) {
            String keyDerivationPath ="";
            String extPubKey = null;
            String childDerivationPath = "/0/*";

            if(matcher.group(1) != null) {
                keyDerivationPath = matcher.group(1);
            }

            extPubKey = matcher.group(2);
            if(matcher.group(3) != null) {
                childDerivationPath = matcher.group(3);
            }

            ExtendedPublicKey extendedPublicKey = ExtendedPublicKey.fromDescriptor(keyDerivationPath, extPubKey, childDerivationPath);
            keys.add(extendedPublicKey);
        }

        return keys;
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(script);
        builder.append("(");

        if(isMultisig()) {
            StringJoiner joiner = new StringJoiner(",");
            joiner.add(Integer.toString(multisigThreshold));
            for(ExtendedPublicKey pubKey : extendedPublicKeys) {
                joiner.add(pubKey.toString());
            }
            builder.append(joiner.toString());
        } else {
            builder.append(getSingletonExtendedPublicKey());
        }

        builder.append(")");

        if(script.contains("(")){
            builder.append(")");
        }

        return builder.toString();
    }
}
