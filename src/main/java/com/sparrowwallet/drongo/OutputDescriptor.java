package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.address.*;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Network;
import com.sparrowwallet.drongo.protocol.ProtocolException;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.KeystoreSource;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletModel;

import java.math.BigInteger;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.sparrowwallet.drongo.KeyDerivation.parsePath;

public class OutputDescriptor {
    private static final String INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    private static final String CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    private static final Pattern XPUB_PATTERN = Pattern.compile("(\\[[^\\]]+\\])?(.pub[^/\\,)]{100,112})(/[/\\d*'hH]+)?");
    private static final Pattern MULTI_PATTERN = Pattern.compile("multi\\(([\\d+])");
    private static final Pattern KEY_ORIGIN_PATTERN = Pattern.compile("\\[([A-Fa-f0-9]{8})([/\\d'hH]+)\\]");
    private static final Pattern CHECKSUM_PATTERN = Pattern.compile("#([" + CHECKSUM_CHARSET + "]{8})$");

    private final Network network;
    private final ScriptType scriptType;
    private final int multisigThreshold;
    private final Map<ExtendedKey, KeyDerivation> extendedPublicKeys;
    private final Map<ExtendedKey, String> mapChildrenDerivations;

    public OutputDescriptor(Network network, ScriptType scriptType, ExtendedKey extendedPublicKey, KeyDerivation keyDerivation) {
        this(network, scriptType, Collections.singletonMap(extendedPublicKey, keyDerivation));
    }

    public OutputDescriptor(Network network, ScriptType scriptType, Map<ExtendedKey, KeyDerivation> extendedPublicKeys) {
        this(network, scriptType, 0, extendedPublicKeys);
    }

    public OutputDescriptor(Network network, ScriptType scriptType, int multisigThreshold, Map<ExtendedKey, KeyDerivation> extendedPublicKeys) {
        this(network, scriptType, multisigThreshold, extendedPublicKeys, new LinkedHashMap<>());
    }

    public OutputDescriptor(Network network, ScriptType scriptType, int multisigThreshold, Map<ExtendedKey, KeyDerivation> extendedPublicKeys, Map<ExtendedKey, String> mapChildrenDerivations) {
        this.network = network;
        this.scriptType = scriptType;
        this.multisigThreshold = multisigThreshold;
        this.extendedPublicKeys = extendedPublicKeys;
        this.mapChildrenDerivations = mapChildrenDerivations;
    }

    public Set<ExtendedKey> getExtendedPublicKeys() {
        return Collections.unmodifiableSet(extendedPublicKeys.keySet());
    }

    public KeyDerivation getKeyDerivation(ExtendedKey extendedPublicKey) {
        return extendedPublicKeys.get(extendedPublicKey);
    }

    public int getMultisigThreshold() {
        return multisigThreshold;
    }

    public String getChildDerivationPath(ExtendedKey extendedPublicKey) {
        return mapChildrenDerivations.get(extendedPublicKey);
    }

    public boolean describesMultipleAddresses(ExtendedKey extendedPublicKey) {
        return getChildDerivationPath(extendedPublicKey) == null || getChildDerivationPath(extendedPublicKey).endsWith("/*");
    }

    public List<ChildNumber> getReceivingDerivation(ExtendedKey extendedPublicKey, int wildCardReplacement) {
        String childDerivationPath = getChildDerivationPath(extendedPublicKey);
        if(childDerivationPath == null) {
            childDerivationPath = "/0/*";
        }

        if(describesMultipleAddresses(extendedPublicKey)) {
            if(childDerivationPath.endsWith("0/*")) {
                return getChildDerivation(extendedPublicKey.getKey().getChildNumber(), childDerivationPath, wildCardReplacement);
            }

            if(extendedPublicKey.getKeyChildNumber().num() == 0 && childDerivationPath.endsWith("/*")) {
                return getChildDerivation(new ChildNumber(0, extendedPublicKey.getKey().getChildNumber().isHardened()), childDerivationPath, wildCardReplacement);
            }
        }

        throw new IllegalStateException("Cannot derive receiving address from output descriptor " + this.toString());
    }

    public List<ChildNumber> getChangeDerivation(ExtendedKey extendedPublicKey, int wildCardReplacement) {
        String childDerivationPath = getChildDerivationPath(extendedPublicKey);
        if(childDerivationPath == null) {
            childDerivationPath = "/1/*";
        }

        if(describesMultipleAddresses(extendedPublicKey)) {
            if(childDerivationPath.endsWith("0/*")) {
                return getChildDerivation(extendedPublicKey.getKey().getChildNumber(), childDerivationPath.replace("0/*", "1/*"), wildCardReplacement);
            }

            if(childDerivationPath.endsWith("/*")) {
                return getChildDerivation(extendedPublicKey.getKey().getChildNumber(), childDerivationPath, wildCardReplacement);
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

    public List<ChildNumber> getChildDerivation(ExtendedKey extendedPublicKey) {
        return getChildDerivation(extendedPublicKey, 0);
    }

    public List<ChildNumber> getChildDerivation(ExtendedKey extendedPublicKey, int wildCardReplacement) {
        String childDerivationPath = getChildDerivationPath(extendedPublicKey);
        return getChildDerivation(extendedPublicKey.getKey().getChildNumber(), childDerivationPath, wildCardReplacement);
    }

    public boolean isMultisig() {
        return extendedPublicKeys.size() > 1;
    }

    public ExtendedKey getSingletonExtendedPublicKey() {
        if(isMultisig()) {
            throw new IllegalStateException("Output descriptor contains multiple public keys but singleton requested");
        }

        return extendedPublicKeys.keySet().iterator().next();
    }

    public ScriptType getScriptType() {
        return scriptType;
    }

    public boolean describesMultipleAddresses() {
        for(ExtendedKey pubKey : extendedPublicKeys.keySet()) {
            if(describesMultipleAddresses(pubKey)) {
                return false;
            }
        }

        return true;
    }

    public List<ChildNumber> getChildDerivation() {
        List<ChildNumber> lastDerivation = null;
        for(ExtendedKey pubKey : extendedPublicKeys.keySet()) {
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
        return scriptType.getAddress(network, childKey);
    }

    private Address getAddress(Script multisigScript) {
        return scriptType.getAddress(network, multisigScript);
    }

    private Script getMultisigScript(List<ChildNumber> childPath) {
        List<ECKey> keys = new ArrayList<>();
        for(ExtendedKey pubKey : extendedPublicKeys.keySet()) {
            List<ChildNumber> keyPath = getKeyPath(pubKey, childPath);

            keys.add(pubKey.getKey(keyPath));
        }

        return ScriptType.MULTISIG.getOutputScript(multisigThreshold, keys);
    }

    private List<ChildNumber> getKeyPath(ExtendedKey pubKey, List<ChildNumber> childPath) {
        List<ChildNumber> keyPath;
        if(childPath.get(0).num() == 0) {
            keyPath = getReceivingDerivation(pubKey, childPath.get(1).num());
        } else if(childPath.get(0).num() == 1) {
            keyPath = getChangeDerivation(pubKey, childPath.get(1).num());
        } else {
            keyPath = getChildDerivation(pubKey, childPath.get(1).num());
        }

        return keyPath;
    }

    public Wallet toWallet() {
        Wallet wallet = new Wallet(network);
        wallet.setPolicyType(isMultisig() ? PolicyType.MULTI : PolicyType.SINGLE);
        wallet.setScriptType(scriptType);

        for(Map.Entry<ExtendedKey,KeyDerivation> extKeyEntry : extendedPublicKeys.entrySet()) {
            Keystore keystore = new Keystore();
            keystore.setSource(KeystoreSource.SW_WATCH);
            keystore.setWalletModel(WalletModel.SPARROW);
            keystore.setKeyDerivation(extKeyEntry.getValue());
            keystore.setExtendedPublicKey(extKeyEntry.getKey());
            wallet.makeLabelsUnique(keystore);
            wallet.getKeystores().add(keystore);
        }

        wallet.setDefaultPolicy(Policy.getPolicy(wallet.getPolicyType(), wallet.getScriptType(), wallet.getKeystores(), getMultisigThreshold()));
        return wallet;
    }

    public static OutputDescriptor getOutputDescriptor(Wallet wallet) {
        Map<ExtendedKey, KeyDerivation> extendedKeyDerivationMap = new LinkedHashMap<>();
        for(Keystore keystore : wallet.getKeystores()) {
            extendedKeyDerivationMap.put(keystore.getExtendedPublicKey(), keystore.getKeyDerivation());
        }

        return new OutputDescriptor(wallet.getNetwork(), wallet.getScriptType(), wallet.getDefaultPolicy().getNumSignaturesRequired(), extendedKeyDerivationMap);
    }

    // See https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
    public static OutputDescriptor getOutputDescriptor(Network network, String descriptor) {
        ScriptType scriptType = ScriptType.fromDescriptor(descriptor);
        if(scriptType == null) {
            ExtendedKey.Header header = ExtendedKey.Header.fromExtendedKey(descriptor);
            scriptType = header.getDefaultScriptType();
        }

        if(scriptType == null) {
            throw new IllegalArgumentException("Cannot determine script type from descriptor: " + descriptor);
        }

        int threshold = getMultisigThreshold(descriptor);
        return getOutputDescriptorImpl(network, scriptType, threshold, descriptor);
    }

    private static int getMultisigThreshold(String descriptor) {
        Matcher matcher = MULTI_PATTERN.matcher(descriptor);
        if(matcher.find()) {
            String threshold = matcher.group(1);
            return Integer.parseInt(threshold);
        } else {
            return 1;
        }
    }

    private static OutputDescriptor getOutputDescriptorImpl(Network network, ScriptType scriptType, int multisigThreshold, String descriptor) {
        Matcher checksumMatcher = CHECKSUM_PATTERN.matcher(descriptor);
        if(checksumMatcher.find()) {
            String checksum = checksumMatcher.group(1);
            String calculatedChecksum = getChecksum(descriptor.substring(0, checksumMatcher.start()));
            if(!checksum.equals(calculatedChecksum)) {
                throw new IllegalArgumentException("Descriptor checksum invalid - checksum of " + checksum + " did not match calculated checksum of " + calculatedChecksum);
            }
        }

        Map<ExtendedKey, KeyDerivation> keyDerivationMap = new LinkedHashMap<>();
        Map<ExtendedKey, String> keyChildDerivationMap = new LinkedHashMap<>();
        Matcher matcher = XPUB_PATTERN.matcher(descriptor);
        while(matcher.find()) {
            String masterFingerprint = null;
            String keyDerivationPath = null;
            String extPubKey;
            String childDerivationPath = null;

            if(matcher.group(1) != null) {
                String keyOrigin = matcher.group(1);
                Matcher keyOriginMatcher = KEY_ORIGIN_PATTERN.matcher(keyOrigin);
                if(keyOriginMatcher.matches()) {
                    byte[] masterFingerprintBytes = Utils.hexToBytes(keyOriginMatcher.group(1));
                    if(masterFingerprintBytes.length != 4) {
                        throw new IllegalArgumentException("Master fingerprint must be 4 bytes: " + Utils.bytesToHex(masterFingerprintBytes));
                    }
                    masterFingerprint = Utils.bytesToHex(masterFingerprintBytes);
                    keyDerivationPath = KeyDerivation.writePath(KeyDerivation.parsePath(keyOriginMatcher.group(2)));
                }
            }

            extPubKey = matcher.group(2);
            if(matcher.group(3) != null) {
                childDerivationPath = matcher.group(3);
            }

            KeyDerivation keyDerivation = new KeyDerivation(masterFingerprint, keyDerivationPath);
            try {
                ExtendedKey extendedPublicKey = ExtendedKey.fromDescriptor(extPubKey);
                keyDerivationMap.put(extendedPublicKey, keyDerivation);
                keyChildDerivationMap.put(extendedPublicKey, childDerivationPath);
            } catch(ProtocolException e) {
                throw new ProtocolException("Invalid xPub: " + e.getMessage());
            }
        }

        return new OutputDescriptor(network, scriptType, multisigThreshold, keyDerivationMap, keyChildDerivationMap);
    }

    private static String getChecksum(String descriptor) {
        BigInteger c = BigInteger.valueOf(1);
        int cls = 0;
        int clscount = 0;
        for(int i = 0; i < descriptor.length(); i++) {
            char ch = descriptor.charAt(i);
            int pos = INPUT_CHARSET.indexOf(ch);

            if(pos < 0) {
                return "";
            }

            c = polyMod(c, pos & 31); // Emit a symbol for the position inside the group, for every character.
            cls = cls * 3 + (pos >> 5); // Accumulate the group numbers
            if(++clscount == 3) {
                // Emit an extra symbol representing the group numbers, for every 3 characters.
                c = polyMod(c, cls);
                cls = 0;
                clscount = 0;
            }
        }

        if(clscount > 0) {
            c = polyMod(c, cls);
        }
        for(int j = 0; j < 8; ++j) {
            c = polyMod(c, 0); // Shift further to determine the checksum.
        }
        c = c.xor(BigInteger.valueOf(1)); // Prevent appending zeroes from not affecting the checksum.

        StringBuilder ret = new StringBuilder();
        for(int j = 0; j < 8; ++j) {
            BigInteger index = c.shiftRight(5 * (7 - j)).and(BigInteger.valueOf(31));
            ret.append(CHECKSUM_CHARSET.charAt(index.intValue()));
        }

        return ret.toString();
    }

    private static BigInteger polyMod(BigInteger c, int val)
    {
        byte c0 = c.shiftRight(35).byteValue();
        c = c.and(new BigInteger("7ffffffff", 16)).shiftLeft(5).or(BigInteger.valueOf(val));

        if((c0 & 1) > 0) {
            c = c.xor(new BigInteger("f5dee51989", 16));
        }
        if((c0 & 2) > 0) {
            c = c.xor(new BigInteger("a9fdca3312", 16));
        }
        if((c0 & 4) > 0) {
            c = c.xor(new BigInteger("1bab10e32d", 16));
        }
        if((c0 & 8) > 0) {
            c = c.xor(new BigInteger("3706b1677a", 16));
        }
        if((c0 & 16) > 0) {
            c = c.xor(new BigInteger("644d626ffd", 16));
        }

        return c;
    }

    public String toString() {
        return toString(false);
    }

    public String toString(boolean addChecksum) {
        StringBuilder builder = new StringBuilder();
        builder.append(scriptType.getDescriptor());

        if(isMultisig()) {
            builder.append(ScriptType.MULTISIG.getDescriptor());
            StringJoiner joiner = new StringJoiner(",");
            joiner.add(Integer.toString(multisigThreshold));
            for(ExtendedKey pubKey : extendedPublicKeys.keySet()) {
                String extKeyString = toString(pubKey);
                joiner.add(extKeyString);
            }
            builder.append(joiner.toString());
            builder.append(ScriptType.MULTISIG.getCloseDescriptor());
        } else {
            ExtendedKey extendedPublicKey = getSingletonExtendedPublicKey();
            builder.append(toString(extendedPublicKey));
        }
        builder.append(scriptType.getCloseDescriptor());

        if(addChecksum) {
            String descriptor = builder.toString();
            builder.append("#");
            builder.append(getChecksum(descriptor));
        }

        return builder.toString();
    }

    private String toString(ExtendedKey pubKey) {
        StringBuilder keyBuilder = new StringBuilder();
        KeyDerivation keyDerivation = extendedPublicKeys.get(pubKey);
        if(keyDerivation != null && keyDerivation.getDerivationPath() != null) {
            keyBuilder.append("[");
            if(keyDerivation.getMasterFingerprint() != null) {
                keyBuilder.append(keyDerivation.getMasterFingerprint());
                keyBuilder.append("/");
            }
            keyBuilder.append(keyDerivation.getDerivationPath().replaceFirst("^m?/", ""));
            keyBuilder.append("]");
        }

        if(pubKey != null) {
            keyBuilder.append(pubKey.toString());
        }

        String childDerivation = mapChildrenDerivations.get(pubKey);
        if(childDerivation != null) {
            if(!childDerivation.startsWith("/")) {
                keyBuilder.append("/");
            }

            keyBuilder.append(childDerivation);
        }

        return keyBuilder.toString();
    }
}
