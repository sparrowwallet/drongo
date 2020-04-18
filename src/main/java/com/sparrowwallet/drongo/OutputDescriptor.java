package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.address.*;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptChunk;
import com.sparrowwallet.drongo.protocol.ScriptOpCodes;
import com.sparrowwallet.drongo.protocol.ScriptType;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.sparrowwallet.drongo.KeyDerivation.parsePath;

public class OutputDescriptor {
    private static final Pattern XPUB_PATTERN = Pattern.compile("(\\[[^\\]]+\\])?(.pub[^/\\)]+)(/[/\\d*']+)?");
    private static final Pattern MULTI_PATTERN = Pattern.compile("multi\\(([\\d+])");
    private static final Pattern KEY_ORIGIN_PATTERN = Pattern.compile("\\[([a-f0-9]+)([/\\d']+)\\]");

    private final String script;
    private final int multisigThreshold;
    private final Map<ExtendedPublicKey, KeyDerivation> extendedPublicKeys;
    private final Map<ExtendedPublicKey, String> mapChildrenDerivations;

    public OutputDescriptor(String script, ExtendedPublicKey extendedPublicKey, KeyDerivation keyDerivation) {
        this(script, Collections.singletonMap(extendedPublicKey, keyDerivation));
    }

    public OutputDescriptor(String script, Map<ExtendedPublicKey, KeyDerivation> extendedPublicKeys) {
        this(script, 0, extendedPublicKeys);
    }

    public OutputDescriptor(String script, int multisigThreshold, Map<ExtendedPublicKey, KeyDerivation> extendedPublicKeys) {
        this(script, multisigThreshold, extendedPublicKeys, new LinkedHashMap<>());
    }

    public OutputDescriptor(String script, int multisigThreshold, Map<ExtendedPublicKey, KeyDerivation> extendedPublicKeys, Map<ExtendedPublicKey, String> mapChildrenDerivations) {
        this.script = script;
        this.multisigThreshold = multisigThreshold;
        this.extendedPublicKeys = extendedPublicKeys;
        this.mapChildrenDerivations = mapChildrenDerivations;
    }

    public Set<ExtendedPublicKey> getExtendedPublicKeys() {
        return Collections.unmodifiableSet(extendedPublicKeys.keySet());
    }

    public KeyDerivation getKeyDerivation(ExtendedPublicKey extendedPublicKey) {
        return extendedPublicKeys.get(extendedPublicKey);
    }

    public String getChildDerivationPath(ExtendedPublicKey extendedPublicKey) {
        return mapChildrenDerivations.get(extendedPublicKey);
    }

    public boolean describesMultipleAddresses(ExtendedPublicKey extendedPublicKey) {
        return getChildDerivationPath(extendedPublicKey).endsWith("/*");
    }

    public List<ChildNumber> getReceivingDerivation(ExtendedPublicKey extendedPublicKey, int wildCardReplacement) {
        String childDerivationPath = getChildDerivationPath(extendedPublicKey);
        if(describesMultipleAddresses(extendedPublicKey)) {
            if(childDerivationPath.endsWith("0/*")) {
                return getChildDerivation(extendedPublicKey.getPubKey().getChildNumber(), childDerivationPath, wildCardReplacement);
            }

            if(extendedPublicKey.getPubKeyChildNumber().num() == 0 && childDerivationPath.endsWith("/*")) {
                return getChildDerivation(new ChildNumber(0, extendedPublicKey.getPubKey().getChildNumber().isHardened()), childDerivationPath, wildCardReplacement);
            }
        }

        throw new IllegalStateException("Cannot derive receiving address from output descriptor " + this.toString());
    }

    public List<ChildNumber> getChangeDerivation(ExtendedPublicKey extendedPublicKey, int wildCardReplacement) {
        String childDerivationPath = getChildDerivationPath(extendedPublicKey);
        if(describesMultipleAddresses(extendedPublicKey)) {
            if(childDerivationPath.endsWith("0/*")) {
                return getChildDerivation(extendedPublicKey.getPubKey().getChildNumber(), childDerivationPath.replace("0/*", "1/*"), wildCardReplacement);
            }

            if(extendedPublicKey.getPubKeyChildNumber().num() == 1 && childDerivationPath.endsWith("/*")) {
                return getChildDerivation(new ChildNumber(1, extendedPublicKey.getPubKey().getChildNumber().isHardened()), childDerivationPath, wildCardReplacement);
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

    public List<ChildNumber> getChildDerivation(ExtendedPublicKey extendedPublicKey) {
        return getChildDerivation(extendedPublicKey, 0);
    }

    public List<ChildNumber> getChildDerivation(ExtendedPublicKey extendedPublicKey, int wildCardReplacement) {
        String childDerivationPath = getChildDerivationPath(extendedPublicKey);
        return getChildDerivation(extendedPublicKey.getPubKey().getChildNumber(), childDerivationPath, wildCardReplacement);
    }

    public boolean isMultisig() {
        return extendedPublicKeys.size() > 1;
    }

    public ExtendedPublicKey getSingletonExtendedPublicKey() {
        if(isMultisig()) {
            throw new IllegalStateException("Output descriptor contains multiple public keys but singleton requested");
        }

        return extendedPublicKeys.keySet().iterator().next();
    }

    public String getScript() {
        return script;
    }

    public boolean describesMultipleAddresses() {
        for(ExtendedPublicKey pubKey : extendedPublicKeys.keySet()) {
            if(describesMultipleAddresses(pubKey)) {
                return false;
            }
        }

        return true;
    }

    public List<ChildNumber> getChildDerivation() {
        List<ChildNumber> lastDerivation = null;
        for(ExtendedPublicKey pubKey : extendedPublicKeys.keySet()) {
            List<ChildNumber> derivation = getChildDerivation(pubKey);
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

        return getReceivingDerivation(getSingletonExtendedPublicKey(), wildCardReplacement);
    }

    public List<ChildNumber> getChangeDerivation(int wildCardReplacement) {
        if(isMultisig()) {
            List<ChildNumber> path = new ArrayList<>();
            path.add(new ChildNumber(1));
            path.add(new ChildNumber(wildCardReplacement));
            return path;
        }

        return getChangeDerivation(getSingletonExtendedPublicKey(), wildCardReplacement);
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
            Script receivingP2wpkhScript = ScriptType.P2WPKH.getOutputScript(childKey.getPubKeyHash());
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

        for(ExtendedPublicKey pubKey : extendedPublicKeys.keySet()) {
            List<ChildNumber> keyPath = null;
            if(path.get(0).num() == 0) {
                keyPath = getReceivingDerivation(pubKey, path.get(1).num());
            } else if(path.get(0).num() == 1) {
                keyPath = getChangeDerivation(pubKey, path.get(1).num());
            } else {
                keyPath = getChildDerivation(pubKey, path.get(1).num());
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
            return getOutputDescriptorImpl("pkh", 0, descriptor);
        } else if(descriptor.startsWith("wpkh") || descriptor.startsWith("zpub")) {
            return getOutputDescriptorImpl("wpkh", 0, descriptor);
        } else if(descriptor.startsWith("sh(wpkh") || descriptor.startsWith("ypub")) {
            return getOutputDescriptorImpl("sh(wpkh", 0, descriptor);
        } else if(descriptor.startsWith("sh(multi") || descriptor.startsWith("Ypub")) {
            return getOutputDescriptorImpl("sh(multi", getMultsigThreshold(descriptor), descriptor);
        } else if(descriptor.startsWith("wsh(multi") || descriptor.startsWith("Zpub")) {
            return getOutputDescriptorImpl("wsh(multi", getMultsigThreshold(descriptor), descriptor);
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

    private static OutputDescriptor getOutputDescriptorImpl(String script, int multisigThreshold, String descriptor) {
        Map<ExtendedPublicKey, KeyDerivation> keyDerivationMap = new LinkedHashMap<>();
        Map<ExtendedPublicKey, String> keyChildDerivationMap = new LinkedHashMap<>();
        Matcher matcher = XPUB_PATTERN.matcher(descriptor);
        while(matcher.find()) {
            String masterFingerprint = null;
            String keyDerivationPath = null;
            String extPubKey = null;
            String childDerivationPath = "/0/*";

            if(matcher.group(1) != null) {
                String keyOrigin = matcher.group(1);
                Matcher keyOriginMatcher = KEY_ORIGIN_PATTERN.matcher(keyOrigin);
                if(keyOriginMatcher.matches()) {
                    masterFingerprint = keyOriginMatcher.group(1);
                    keyDerivationPath = "m" + keyOriginMatcher.group(2);
                }
            }

            extPubKey = matcher.group(2);
            if(matcher.group(3) != null) {
                childDerivationPath = matcher.group(3);
            }

            KeyDerivation keyDerivation = new KeyDerivation(masterFingerprint, keyDerivationPath);
            ExtendedPublicKey extendedPublicKey = ExtendedPublicKey.fromDescriptor(extPubKey);
            keyDerivationMap.put(extendedPublicKey, keyDerivation);
            keyChildDerivationMap.put(extendedPublicKey, childDerivationPath);
        }

        return new OutputDescriptor(script, multisigThreshold, keyDerivationMap, keyChildDerivationMap);
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(script);
        builder.append("(");

        if(isMultisig()) {
            StringJoiner joiner = new StringJoiner(",");
            joiner.add(Integer.toString(multisigThreshold));
            for(ExtendedPublicKey pubKey : extendedPublicKeys.keySet()) {
                joiner.add(pubKey.toString());
                joiner.add(mapChildrenDerivations.get(pubKey));
            }
            builder.append(joiner.toString());
        } else {
            ExtendedPublicKey extendedPublicKey = getSingletonExtendedPublicKey();
            builder.append(extendedPublicKey);
            builder.append(mapChildrenDerivations.get(extendedPublicKey));
        }

        builder.append(")");

        if(script.contains("(")){
            builder.append(")");
        }

        return builder.toString();
    }
}
