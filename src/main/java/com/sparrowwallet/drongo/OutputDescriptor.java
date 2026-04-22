package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.address.*;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.crypto.DumpedPrivateKey;
import com.sparrowwallet.drongo.protocol.ProtocolException;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentScanAddress;
import com.sparrowwallet.drongo.wallet.*;

import java.math.BigInteger;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.sparrowwallet.drongo.KeyDerivation.parsePath;

public class OutputDescriptor {
    private static final String INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    private static final String CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    public static final Pattern XPUB_PATTERN = Pattern.compile("(\\[[^\\]]+\\])?(.(?:pub|prv)[^/\\,)]{100,112})(/[/\\d*'hH<>;]+)?");
    private static final Pattern PUBKEY_PATTERN = Pattern.compile("(\\[[^\\]]+\\])?(0[23][0-9a-fA-F]{64})");
    private static final Pattern MULTI_PATTERN = Pattern.compile("multi\\((\\d+)");
    public static final Pattern KEY_ORIGIN_PATTERN = Pattern.compile("\\[([A-Fa-f0-9]{8})([/\\d'hH]+)?\\]");
    private static final Pattern MULTIPATH_PATTERN = Pattern.compile("<([\\d*'hH;]+)>");
    private static final Pattern CHECKSUM_PATTERN = Pattern.compile("#([" + CHECKSUM_CHARSET + "]{8})$");
    private static final Pattern ANNOTATION_PATTERN = Pattern.compile("([a-zA-Z]+)=([0-9]+)");

    public static final String ANNOTATION_BLOCK_HEIGHT = "bh";
    public static final String ANNOTATION_GAP_LIMIT = "gl";
    public static final String ANNOTATION_MAX_LABEL = "ml";

    private final ScriptType scriptType;
    private final int multisigThreshold;
    private final Map<ExtendedKey, KeyDerivation> extendedPublicKeys;
    private final Map<ExtendedKey, String> mapChildrenDerivations;
    private final Map<ExtendedKey, String> mapExtendedPublicKeyLabels;
    private final Map<ExtendedKey, ExtendedKey> extendedMasterPrivateKeys;
    private final Map<SilentPaymentScanAddress, KeyDerivation> silentPaymentScanAddresses;
    private final Map<SilentPaymentScanAddress, String> mapSilentPaymentLabels;
    private final Map<String, Integer> annotations;

    public OutputDescriptor(ScriptType scriptType, ExtendedKey extendedPublicKey, KeyDerivation keyDerivation) {
        this(scriptType, Collections.singletonMap(extendedPublicKey, keyDerivation));
    }

    public OutputDescriptor(ScriptType scriptType, ExtendedKey extendedPublicKey, KeyDerivation keyDerivation, String extendedPublicKeyLabel) {
        this(scriptType, 0, Collections.singletonMap(extendedPublicKey, keyDerivation), new LinkedHashMap<>(), extendedPublicKeyLabel == null ? new LinkedHashMap<>() : Collections.singletonMap(extendedPublicKey, extendedPublicKeyLabel));
    }

    public OutputDescriptor(ScriptType scriptType, Map<ExtendedKey, KeyDerivation> extendedPublicKeys) {
        this(scriptType, 0, extendedPublicKeys);
    }

    public OutputDescriptor(ScriptType scriptType, int multisigThreshold, Map<ExtendedKey, KeyDerivation> extendedPublicKeys) {
        this(scriptType, multisigThreshold, extendedPublicKeys, new LinkedHashMap<>());
    }

    public OutputDescriptor(ScriptType scriptType, int multisigThreshold, Map<ExtendedKey, KeyDerivation> extendedPublicKeys, Map<ExtendedKey, String> mapChildrenDerivations) {
        this(scriptType, multisigThreshold, extendedPublicKeys, mapChildrenDerivations, new LinkedHashMap<>());
    }

    public OutputDescriptor(ScriptType scriptType, int multisigThreshold, Map<ExtendedKey, KeyDerivation> extendedPublicKeys, Map<ExtendedKey, String> mapChildrenDerivations, Map<ExtendedKey, String> mapExtendedPublicKeyLabels) {
        this(scriptType, multisigThreshold, extendedPublicKeys, mapChildrenDerivations, mapExtendedPublicKeyLabels, new LinkedHashMap<>());
    }

    public OutputDescriptor(ScriptType scriptType, int multisigThreshold, Map<ExtendedKey, KeyDerivation> extendedPublicKeys, Map<ExtendedKey, String> mapChildrenDerivations, Map<ExtendedKey, String> mapExtendedPublicKeyLabels, Map<ExtendedKey, ExtendedKey> extendedMasterPrivateKeys) {
        this(scriptType, multisigThreshold, extendedPublicKeys, mapChildrenDerivations, mapExtendedPublicKeyLabels, extendedMasterPrivateKeys, new LinkedHashMap<>());
    }

    public OutputDescriptor(ScriptType scriptType, int multisigThreshold, Map<ExtendedKey, KeyDerivation> extendedPublicKeys, Map<ExtendedKey, String> mapChildrenDerivations, Map<ExtendedKey, String> mapExtendedPublicKeyLabels, Map<ExtendedKey, ExtendedKey> extendedMasterPrivateKeys, Map<String, Integer> annotations) {
        this.scriptType = scriptType;
        this.multisigThreshold = multisigThreshold;
        this.extendedPublicKeys = extendedPublicKeys;
        this.mapChildrenDerivations = mapChildrenDerivations;
        this.mapExtendedPublicKeyLabels = mapExtendedPublicKeyLabels;
        this.extendedMasterPrivateKeys = extendedMasterPrivateKeys;
        this.silentPaymentScanAddresses = new LinkedHashMap<>();
        this.mapSilentPaymentLabels = new LinkedHashMap<>();
        this.annotations = annotations;
    }

    public OutputDescriptor(Map<SilentPaymentScanAddress, KeyDerivation> silentPaymentScanAddresses, Map<SilentPaymentScanAddress, String> mapSilentPaymentLabels) {
        this(silentPaymentScanAddresses, mapSilentPaymentLabels, new LinkedHashMap<>());
    }

    public OutputDescriptor(Map<SilentPaymentScanAddress, KeyDerivation> silentPaymentScanAddresses, Map<SilentPaymentScanAddress, String> mapSilentPaymentLabels, Map<String, Integer> annotations) {
        this.scriptType = ScriptType.P2TR;
        this.multisigThreshold = 1;
        this.extendedPublicKeys = new LinkedHashMap<>();
        this.mapChildrenDerivations = new LinkedHashMap<>();
        this.mapExtendedPublicKeyLabels = new LinkedHashMap<>();
        this.extendedMasterPrivateKeys = new LinkedHashMap<>();
        this.silentPaymentScanAddresses = silentPaymentScanAddresses;
        this.mapSilentPaymentLabels = mapSilentPaymentLabels;
        this.annotations = annotations;
    }

    public Set<ExtendedKey> getExtendedPublicKeys() {
        return Collections.unmodifiableSet(extendedPublicKeys.keySet());
    }

    public Map<ExtendedKey, KeyDerivation> getExtendedPublicKeysMap() {
        return Collections.unmodifiableMap(extendedPublicKeys);
    }

    public KeyDerivation getKeyDerivation(ExtendedKey extendedPublicKey) {
        return extendedPublicKeys.get(extendedPublicKey);
    }

    public int getMultisigThreshold() {
        return multisigThreshold;
    }

    public Map<ExtendedKey, String> getChildDerivationsMap() {
        return Collections.unmodifiableMap(mapChildrenDerivations);
    }

    public String getChildDerivationPath(ExtendedKey extendedPublicKey) {
        return mapChildrenDerivations.get(extendedPublicKey);
    }

    public String getExtendedPublicKeyLabel(ExtendedKey extendedPublicKey) {
        return mapExtendedPublicKeyLabels.get(extendedPublicKey);
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

    public boolean isCosigner() {
        return !isMultisig() && scriptType.isAllowed(PolicyType.MULTI_HD);
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

    public Map<SilentPaymentScanAddress, KeyDerivation> getSilentPaymentScanAddresses() {
        return Collections.unmodifiableMap(silentPaymentScanAddresses);
    }

    public boolean isSilentPayments() {
        return !silentPaymentScanAddresses.isEmpty();
    }

    public Map<String, Integer> getAnnotations() {
        return Collections.unmodifiableMap(annotations);
    }

    public void clearAnnotations() {
        annotations.clear();
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
        return scriptType.getAddress(PolicyType.SINGLE_HD, childKey);
    }

    private Address getAddress(Script multisigScript) {
        return scriptType.getAddress(multisigScript);
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
        if(isSilentPayments()) {
            return toSilentPaymentWallet();
        }

        Wallet wallet = new Wallet();
        wallet.setPolicyType(isMultisig() || isCosigner() ? PolicyType.MULTI_HD : PolicyType.SINGLE_HD);
        wallet.setScriptType(scriptType);

        for(Map.Entry<ExtendedKey,KeyDerivation> extKeyEntry : extendedPublicKeys.entrySet()) {
            ExtendedKey xpub = extKeyEntry.getKey();
            Keystore keystore = new Keystore();
            if(extendedMasterPrivateKeys.containsKey(xpub)) {
                ExtendedKey xprv = extendedMasterPrivateKeys.get(xpub);
                MasterPrivateExtendedKey masterPrivateExtendedKey = new MasterPrivateExtendedKey(xprv.getKey().getPrivKeyBytes(), xprv.getKey().getChainCode());
                String childDerivation = mapChildrenDerivations.get(xpub) == null ? scriptType.getDefaultDerivationPath() : mapChildrenDerivations.get(xpub);
                if(childDerivation.endsWith("/<0;1>/*")) {
                    childDerivation = childDerivation.substring(0, childDerivation.length() - 8);
                } else if(childDerivation.endsWith("/0/*") || childDerivation.endsWith("/1/*")) {
                    childDerivation = childDerivation.substring(0, childDerivation.length() - 4);
                }
                try {
                    keystore = Keystore.fromMasterPrivateExtendedKey(masterPrivateExtendedKey, KeyDerivation.parsePath(childDerivation));
                } catch(MnemonicException e) {
                    throw new RuntimeException(e);
                }
            } else {
                keystore.setSource(KeystoreSource.SW_WATCH);
                keystore.setWalletModel(WalletModel.SPARROW);
                keystore.setKeyDerivation(extKeyEntry.getValue());
                keystore.setExtendedPublicKey(xpub);
            }
            setKeystoreLabel(keystore);
            wallet.makeLabelsUnique(keystore);
            wallet.getKeystores().add(keystore);
        }

        wallet.setDefaultPolicy(Policy.getPolicy(wallet.getPolicyType(), wallet.getScriptType(), wallet.getKeystores(), getMultisigThreshold()));
        applyAnnotations(wallet);

        return wallet;
    }

    private Wallet toSilentPaymentWallet() {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_SP);
        wallet.setScriptType(ScriptType.P2TR);

        Map.Entry<SilentPaymentScanAddress, KeyDerivation> entry = silentPaymentScanAddresses.entrySet().iterator().next();
        SilentPaymentScanAddress spScanAddress = entry.getKey();
        KeyDerivation keyDerivation = entry.getValue();

        Keystore keystore = new Keystore();
        keystore.setSource(KeystoreSource.SW_WATCH);
        keystore.setWalletModel(WalletModel.SPARROW);
        keystore.setKeyDerivation(keyDerivation);
        keystore.setSilentPaymentScanAddress(spScanAddress);
        setKeystoreLabel(keystore);

        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_SP, ScriptType.P2TR, wallet.getKeystores(), 1));
        applyAnnotations(wallet);

        return wallet;
    }

    private void applyAnnotations(Wallet wallet) {
        if(annotations.containsKey(ANNOTATION_BLOCK_HEIGHT)) {
            wallet.setBirthHeight(annotations.get(ANNOTATION_BLOCK_HEIGHT));
        }
        if(annotations.containsKey(ANNOTATION_GAP_LIMIT) && wallet.getPolicyType() != PolicyType.SINGLE_SP) {
            wallet.setGapLimit(annotations.get(ANNOTATION_GAP_LIMIT));
        }
    }

    public Wallet toKeystoreWallet(String masterFingerprint) {
        if(isSilentPayments()) {
            Wallet wallet = toSilentPaymentWallet();
            if(masterFingerprint != null) {
                KeyDerivation existing = wallet.getKeystores().getFirst().getKeyDerivation();
                wallet.getKeystores().getFirst().setKeyDerivation(new KeyDerivation(masterFingerprint, existing.getDerivationPath()));
            }

            return wallet;
        }

        Wallet wallet = new Wallet();
        if(isMultisig()) {
            throw new IllegalStateException("Multisig output descriptors are unsupported.");
        }

        ExtendedKey extendedKey = getSingletonExtendedPublicKey();
        if(masterFingerprint == null) {
            masterFingerprint = getKeyDerivation(extendedKey).getMasterFingerprint();
        }

        wallet.setScriptType(getScriptType());
        Keystore keystore = new Keystore();
        keystore.setKeyDerivation(new KeyDerivation(masterFingerprint, KeyDerivation.writePath(getKeyDerivation(extendedKey).getDerivation())));
        keystore.setExtendedPublicKey(extendedKey);
        setKeystoreLabel(keystore);
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(isCosigner() ? PolicyType.MULTI_HD : PolicyType.SINGLE_HD, wallet.getScriptType(), wallet.getKeystores(), 1));
        applyAnnotations(wallet);

        return wallet;
    }

    public void setKeystoreLabel(Keystore keystore) {
        String label = null;
        if(keystore.getExtendedPublicKey() != null && mapExtendedPublicKeyLabels.get(keystore.getExtendedPublicKey()) != null) {
            label = mapExtendedPublicKeyLabels.get(keystore.getExtendedPublicKey());
        } else if(keystore.getSilentPaymentScanAddress() != null && mapSilentPaymentLabels.get(keystore.getSilentPaymentScanAddress()) != null) {
            label = mapSilentPaymentLabels.get(keystore.getSilentPaymentScanAddress());
        }
        if(label != null) {
            label = label.trim();
            if(label.length() > Keystore.MAX_LABEL_LENGTH) {
                label = label.substring(0, Keystore.MAX_LABEL_LENGTH);
            }
            keystore.setLabel(label);
        }
    }

    public static String toDescriptorString(Address address) {
        return "addr(" + address + ")";
    }

    public static OutputDescriptor getOutputDescriptor(Wallet wallet) {
        return getOutputDescriptor(wallet, null);
    }

    public static OutputDescriptor getOutputDescriptor(Wallet wallet, KeyPurpose keyPurpose) {
        return getOutputDescriptor(wallet, keyPurpose, null);
    }

    public static OutputDescriptor getOutputDescriptor(Wallet wallet, KeyPurpose keyPurpose, Integer index) {
        return getOutputDescriptor(wallet, keyPurpose == null ? null : List.of(keyPurpose), index);
    }

    public static OutputDescriptor getOutputDescriptor(Wallet wallet, List<KeyPurpose> keyPurposes, Integer index) {
        Map<String, Integer> annotations = getWalletAnnotations(wallet);

        if(wallet.getPolicyType() == PolicyType.SINGLE_SP) {
            Keystore keystore = wallet.getKeystores().getFirst();
            Map<SilentPaymentScanAddress, KeyDerivation> spMap = new LinkedHashMap<>();
            spMap.put(keystore.getSilentPaymentScanAddress(), keystore.getKeyDerivation());

            return new OutputDescriptor(spMap, new LinkedHashMap<>(), annotations);
        }

        Map<ExtendedKey, KeyDerivation> extendedKeyDerivationMap = new LinkedHashMap<>();
        Map<ExtendedKey, String> extendedKeyChildDerivationMap = new LinkedHashMap<>();
        for(Keystore keystore : wallet.getKeystores()) {
            extendedKeyDerivationMap.put(keystore.getExtendedPublicKey(), keystore.getKeyDerivation());
            if(keyPurposes != null) {
                String chain;
                if(keyPurposes.size() == 1) {
                    chain = Integer.toString(keyPurposes.get(0).getPathIndex().num());
                } else {
                    StringJoiner joiner = new StringJoiner(";");
                    keyPurposes.forEach(keyPurpose -> joiner.add(Integer.toString(keyPurpose.getPathIndex().num())));
                    chain = "<" + joiner + ">";
                }

                extendedKeyChildDerivationMap.put(keystore.getExtendedPublicKey(), chain + "/" + (index == null ? "*" : index));
            }
        }

        return new OutputDescriptor(wallet.getScriptType(), wallet.getDefaultPolicy().getNumSignaturesRequired(), extendedKeyDerivationMap, extendedKeyChildDerivationMap);
    }

    private static Map<String, Integer> getWalletAnnotations(Wallet wallet) {
        Map<String, Integer> annotations = new LinkedHashMap<>();
        if(wallet.getBirthHeight() != null) {
            annotations.put(ANNOTATION_BLOCK_HEIGHT, wallet.getBirthHeight());
        }
        if(wallet.gapLimit() != null && wallet.getPolicyType() != PolicyType.SINGLE_SP) {
            annotations.put(ANNOTATION_GAP_LIMIT, wallet.getGapLimit());
        }

        return annotations;
    }

    // See https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
    public static OutputDescriptor getOutputDescriptor(String descriptor) {
        return getOutputDescriptor(descriptor, new LinkedHashMap<>());
    }

    public static OutputDescriptor getOutputDescriptor(String descriptor, Map<ExtendedKey, String> mapExtendedPublicKeyLabels) {
        Matcher checksumMatcher = CHECKSUM_PATTERN.matcher(descriptor);
        if(checksumMatcher.find()) {
            String checksum = checksumMatcher.group(1);
            String calculatedChecksum = getChecksum(descriptor.substring(0, checksumMatcher.start()));
            if(!checksum.equals(calculatedChecksum)) {
                throw new IllegalArgumentException("Descriptor checksum invalid - checksum of " + checksum + " did not match calculated checksum of " + calculatedChecksum);
            }
            descriptor = descriptor.substring(0, checksumMatcher.start());
        }

        Map<String, Integer> annotations = new LinkedHashMap<>();
        int annotationStart = descriptor.indexOf('?');
        if(annotationStart >= 0) {
            annotations = parseAnnotations(descriptor.substring(annotationStart + 1));
            descriptor = descriptor.substring(0, annotationStart);
        }

        if(descriptor.toLowerCase(Locale.ROOT).startsWith("sp(")) {
            return parseSilentPaymentDescriptor(descriptor, annotations);
        }

        ScriptType scriptType = ScriptType.fromDescriptor(descriptor);
        if(scriptType == null) {
            ExtendedKey.Header header = ExtendedKey.Header.fromExtendedKey(descriptor);
            scriptType = header.getDefaultScriptType();
        }

        if(scriptType == null) {
            throw new IllegalArgumentException("Cannot determine script type from descriptor: " + descriptor);
        }

        int threshold = getMultisigThreshold(descriptor);
        return getOutputDescriptorImpl(scriptType, threshold, descriptor, mapExtendedPublicKeyLabels, annotations);
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

    private static OutputDescriptor getOutputDescriptorImpl(ScriptType scriptType, int multisigThreshold, String descriptor, Map<ExtendedKey, String> mapExtendedPublicKeyLabels, Map<String, Integer> annotations) {
        Map<ExtendedKey, KeyDerivation> keyDerivationMap = new LinkedHashMap<>();
        Map<ExtendedKey, String> keyChildDerivationMap = new LinkedHashMap<>();
        Map<ExtendedKey, ExtendedKey> masterPrivateKeyMap = new LinkedHashMap<>();
        Matcher matcher = XPUB_PATTERN.matcher(descriptor);
        while(matcher.find()) {
            String keyOriginAndExtKey = (matcher.group(1) != null ? matcher.group(1) : "") + matcher.group(2);
            KeyDerivationAndKey originResult = parseKeyOrigin(keyOriginAndExtKey);
            KeyDerivation keyDerivation = originResult.keyDerivation();
            String extKey = originResult.key();
            String childDerivationPath = matcher.group(3);
            try {
                ExtendedKey extendedKey = ExtendedKey.fromDescriptor(extKey);
                if(childDerivationPath != null) {
                    try {
                        List<ChildNumber> childPath = KeyDerivation.parsePath(childDerivationPath.replace("<0;1>", "0"));
                        if(childPath.size() > 2 && (extendedKey.getKey().hasPrivKey() || childPath.stream().noneMatch(ChildNumber::isHardened))) {
                            childDerivationPath = childDerivationPath.substring(childDerivationPath.lastIndexOf("/", childDerivationPath.lastIndexOf("/") - 1));
                            childPath = childPath.subList(0, childPath.size() - 2);
                            if(keyDerivation.getMasterFingerprint() == null) {
                                keyDerivation = new KeyDerivation(Utils.bytesToHex(extendedKey.getKey().getFingerprint()), keyDerivation.getDerivationPath());
                            }
                            keyDerivation = keyDerivation.extend(childPath);
                            childPath.addFirst(extendedKey.getKeyChildNumber());
                            DeterministicKey derivedKey = extendedKey.getKey(childPath);
                            DeterministicKey pubKey = new DeterministicKey(List.of(derivedKey.getPath().getLast()), derivedKey.getChainCode(), derivedKey.getPubKey(), derivedKey.getDepth(), derivedKey.getParentFingerprint());
                            extendedKey = new ExtendedKey(pubKey, pubKey.getParentFingerprint(), childPath.getLast());
                        }
                    } catch(Exception e) {
                        //ignore and continue
                    }
                }
                if(extendedKey.getKey().hasPrivKey()) {
                    ExtendedKey privateExtendedKey = extendedKey;
                    List<ChildNumber> derivation = keyDerivation.getDerivation();
                    int depth = derivation.isEmpty() ? scriptType.getDefaultDerivation().size() : derivation.size();
                    DeterministicKey prvKey = extendedKey.getKey();
                    DeterministicKey pubKey = new DeterministicKey(List.of(prvKey.getPath().getLast()), prvKey.getChainCode(), prvKey.getPubKey(), depth, extendedKey.getParentFingerprint());
                    extendedKey = new ExtendedKey(pubKey, pubKey.getParentFingerprint(), extendedKey.getKeyChildNumber());

                    if(derivation.isEmpty()) {
                        masterPrivateKeyMap.put(extendedKey, privateExtendedKey);
                    }
                }
                keyDerivationMap.put(extendedKey, keyDerivation);
                keyChildDerivationMap.put(extendedKey, childDerivationPath);
            } catch(ProtocolException e) {
                throw new ProtocolException("Invalid xpub: " + e.getMessage());
            }
        }

        if(keyDerivationMap.isEmpty()) {
            Matcher pubKeyMatcher = PUBKEY_PATTERN.matcher(descriptor);
            if(pubKeyMatcher.find()) {
                throw new IllegalArgumentException("Descriptors with single public keys are not supported - use descriptors with xpubs");
            }
        }

        return new OutputDescriptor(scriptType, multisigThreshold, keyDerivationMap, keyChildDerivationMap, mapExtendedPublicKeyLabels, masterPrivateKeyMap, annotations);
    }

    private static OutputDescriptor parseSilentPaymentDescriptor(String descriptor, Map<String, Integer> annotations) {
        if(!descriptor.startsWith("sp(") || !descriptor.endsWith(")")) {
            throw new IllegalArgumentException("Invalid sp() descriptor format");
        }
        String inner = descriptor.substring(3, descriptor.length() - 1);

        int commaIndex = inner.indexOf(',');
        if(commaIndex < 0) {
            return parseSingleArgSp(inner.trim(), annotations);
        } else {
            return parseTwoArgSp(inner.substring(0, commaIndex).trim(), inner.substring(commaIndex + 1).trim(), annotations);
        }
    }

    private record KeyDerivationAndKey(KeyDerivation keyDerivation, String key) {}

    private static KeyDerivationAndKey parseKeyOrigin(String arg) {
        KeyDerivation keyDerivation = new KeyDerivation(null, (String)null);
        if(arg.startsWith("[")) {
            int closeBracket = arg.indexOf(']');
            if(closeBracket < 0) {
                throw new IllegalArgumentException("Unclosed key origin bracket in descriptor");
            }
            String keyOrigin = arg.substring(0, closeBracket + 1);
            Matcher keyOriginMatcher = KEY_ORIGIN_PATTERN.matcher(keyOrigin);
            if(keyOriginMatcher.matches()) {
                byte[] masterFingerprintBytes = keyOriginMatcher.group(1) != null ? Utils.hexToBytes(keyOriginMatcher.group(1)) : new byte[4];
                if(masterFingerprintBytes.length != 4) {
                    throw new IllegalArgumentException("Master fingerprint must be 4 bytes: " + Utils.bytesToHex(masterFingerprintBytes));
                }
                String masterFingerprint = Utils.bytesToHex(masterFingerprintBytes);
                String keyDerivationPath = KeyDerivation.writePath(KeyDerivation.parsePath(keyOriginMatcher.group(2)));
                keyDerivation = new KeyDerivation(masterFingerprint, keyDerivationPath);
            }
            arg = arg.substring(closeBracket + 1);
        }

        return new KeyDerivationAndKey(keyDerivation, arg);
    }

    private static OutputDescriptor parseSingleArgSp(String arg, Map<String, Integer> annotations) {
        KeyDerivationAndKey originResult = parseKeyOrigin(arg);
        KeyDerivation keyDerivation = originResult.keyDerivation();
        arg = originResult.key();

        String lowerArg = arg.toLowerCase(Locale.ROOT);
        String scanHrp = Network.get().getSilentPaymentsScanKeyHrp();
        String spendHrp = Network.get().getSilentPaymentsSpendKeyHrp();
        if(!lowerArg.startsWith(scanHrp + "1") && !lowerArg.startsWith(spendHrp + "1")) {
            throw new IllegalArgumentException("Single argument sp() descriptor requires spscan or spspend encoded key, got: " + arg);
        }

        SilentPaymentScanAddress spScanAddress = SilentPaymentScanAddress.fromKeyString(arg);
        Map<SilentPaymentScanAddress, KeyDerivation> spMap = new LinkedHashMap<>();
        spMap.put(spScanAddress, keyDerivation);

        return new OutputDescriptor(spMap, new LinkedHashMap<>(), annotations);
    }

    private static OutputDescriptor parseTwoArgSp(String scanArg, String spendArg, Map<String, Integer> annotations) {
        KeyDerivationAndKey originResult = parseKeyOrigin(scanArg);
        KeyDerivation keyDerivation = originResult.keyDerivation();
        if(keyDerivation.getDerivation().size() > 2) {
            List<ChildNumber> accountDerivation = keyDerivation.getDerivation().subList(0, keyDerivation.getDerivation().size() - 2);
            if(KeyDerivation.getBip352ScanDerivation(accountDerivation).equals(keyDerivation.getDerivation())) {
                keyDerivation = new KeyDerivation(keyDerivation.getMasterFingerprint(), accountDerivation);
            }
        }

        ECKey scanPrivateKey = parseSilentPaymentScanKey(originResult.key());
        ECKey spendKey = parseSilentPaymentSpendKey(spendArg);

        ECKey spendPubKey = spendKey.isPubKeyOnly() ? spendKey : ECKey.fromPublicOnly(spendKey.getPubKey());
        SilentPaymentScanAddress spScanAddress = new SilentPaymentScanAddress(scanPrivateKey, spendPubKey);
        Map<SilentPaymentScanAddress, KeyDerivation> spMap = new LinkedHashMap<>();
        spMap.put(spScanAddress, keyDerivation);

        return new OutputDescriptor(spMap, new LinkedHashMap<>(), annotations);
    }

    private static ECKey parseSilentPaymentScanKey(String arg) {
        Matcher xprvMatcher = XPUB_PATTERN.matcher(arg);
        if(xprvMatcher.matches()) {
            String extKeyStr = xprvMatcher.group(2);
            String childPath = xprvMatcher.group(3);
            ExtendedKey extKey = ExtendedKey.fromDescriptor(extKeyStr);
            if(!extKey.getKey().hasPrivKey()) {
                throw new IllegalArgumentException("The scan key must be private, and not an xpub: " + extKeyStr);
            }
            if(childPath != null) {
                List<ChildNumber> path = KeyDerivation.parsePath(childPath);
                path.addFirst(extKey.getKeyChildNumber());
                DeterministicKey derived = extKey.getKey(path);

                return ECKey.fromPrivate(derived.getPrivKeyBytes(), true);
            }

            return ECKey.fromPrivate(extKey.getKey().getPrivKeyBytes(), true);
        }

        DumpedPrivateKey dpk;
        try {
            dpk = DumpedPrivateKey.fromBase58(arg);
        } catch(Exception e) {
            throw new IllegalArgumentException("Cannot parse sp() scan key as xprv or WIF: " + arg, e);
        }

        ECKey key = dpk.getKey();
        if(!key.isCompressed()) {
            throw new IllegalArgumentException("Uncompressed keys are not allowed in sp() descriptors");
        }

        return key;
    }

    private static ECKey parseSilentPaymentSpendKey(String arg) {
        if(arg.startsWith("[")) {
            int closeBracket = arg.indexOf(']');
            if(closeBracket >= 0) {
                arg = arg.substring(closeBracket + 1);
            }
        }

        Matcher xpubMatcher = XPUB_PATTERN.matcher(arg);
        if(xpubMatcher.matches()) {
            String extKeyStr = xpubMatcher.group(2);
            String childPath = xpubMatcher.group(3);
            ExtendedKey extKey = ExtendedKey.fromDescriptor(extKeyStr);
            if(childPath != null) {
                List<ChildNumber> path = KeyDerivation.parsePath(childPath);
                path.addFirst(extKey.getKeyChildNumber());
                DeterministicKey derived = extKey.getKey(path);

                return extKey.getKey().hasPrivKey() ? ECKey.fromPrivate(derived.getPrivKeyBytes(), true) : ECKey.fromPublicOnly(derived.getPubKey());
            }

            return extKey.getKey().hasPrivKey() ? ECKey.fromPrivate(extKey.getKey().getPrivKeyBytes(), true) : ECKey.fromPublicOnly(extKey.getKey().getPubKey());
        }

        Matcher pubKeyMatcher = PUBKEY_PATTERN.matcher(arg);
        if(pubKeyMatcher.matches()) {
            return ECKey.fromPublicOnly(Utils.hexToBytes(pubKeyMatcher.group(2)));
        }

        throw new IllegalArgumentException("Cannot parse sp() spend key as xpub, xprv, or compressed pubkey: " + arg);
    }

    private static Map<String, Integer> parseAnnotations(String annotationString) {
        Map<String, Integer> annotations = new LinkedHashMap<>();
        String[] pairs = annotationString.split("&");
        for(String pair : pairs) {
            Matcher matcher = ANNOTATION_PATTERN.matcher(pair);
            if(matcher.matches()) {
                String key = matcher.group(1).toLowerCase(Locale.ROOT);
                if(!annotations.containsKey(key)) {
                    annotations.put(key, Integer.parseInt(matcher.group(2)));
                }
            }
        }

        return annotations;
    }

    public static String normalize(String descriptor) {
        String normalized = descriptor.replaceAll("'", "h");

        int checksumHash = normalized.lastIndexOf('#');
        if(checksumHash > -1) {
            normalized = normalized.substring(0, checksumHash);
        }

        return normalized + "#" + getChecksum(normalized);
    }

    private static String getChecksum(String descriptor) {
        BigInteger c = BigInteger.valueOf(1);
        int cls = 0;
        int clscount = 0;
        for(int i = 0; i < descriptor.length(); i++) {
            char ch = descriptor.charAt(i);
            int pos = INPUT_CHARSET.indexOf(ch);

            if(pos < 0) {
                continue;
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
        c = c.and(new BigInteger("7ffffffff", 16)).shiftLeft(5).xor(BigInteger.valueOf(val));

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
        return toString(true, addChecksum);
    }

    public String toString(boolean addKeyOrigin, boolean addChecksum) {
        return toString(addKeyOrigin, true, addChecksum);
    }

    public String toString(boolean addKeyOrigin, boolean addKey, boolean addChecksum) {
        StringBuilder builder = new StringBuilder();

        if(isSilentPayments()) {
            Map.Entry<SilentPaymentScanAddress, KeyDerivation> entry = silentPaymentScanAddresses.entrySet().iterator().next();
            builder.append("sp(");
            builder.append(writeKey(entry.getKey(), entry.getValue(), addKeyOrigin));
            builder.append(")");
        } else {
            builder.append(scriptType.getDescriptor());

            if(isMultisig()) {
                builder.append(ScriptType.MULTISIG.getDescriptor());
                StringJoiner joiner = new StringJoiner(",");
                joiner.add(Integer.toString(multisigThreshold));
                for(ExtendedKey pubKey : sortExtendedPubKeys(extendedPublicKeys.keySet())) {
                    String extKeyString = toString(pubKey, addKeyOrigin, addKey);
                    joiner.add(extKeyString);
                }
                builder.append(joiner.toString());
                builder.append(ScriptType.MULTISIG.getCloseDescriptor());
            } else {
                ExtendedKey extendedPublicKey = getSingletonExtendedPublicKey();
                builder.append(toString(extendedPublicKey, addKeyOrigin, addKey));
            }
            builder.append(scriptType.getCloseDescriptor());
        }

        if(!annotations.isEmpty()) {
            builder.append("?");
            StringJoiner annotationJoiner = new StringJoiner("&");
            for(Map.Entry<String, Integer> entry : annotations.entrySet()) {
                annotationJoiner.add(entry.getKey() + "=" + entry.getValue());
            }
            builder.append(annotationJoiner);
        }

        if(addChecksum) {
            String descriptor = builder.toString();
            builder.append("#");
            builder.append(getChecksum(descriptor));
        }

        return builder.toString();
    }

    public List<ExtendedKey> sortExtendedPubKeys(Collection<ExtendedKey> keys) {
        List<ExtendedKey> sortedKeys = new ArrayList<>(keys);
        if(mapChildrenDerivations == null || mapChildrenDerivations.isEmpty() || mapChildrenDerivations.containsKey(null)) {
            return sortedKeys;
        }

        Utils.LexicographicByteArrayComparator lexicographicByteArrayComparator = new Utils.LexicographicByteArrayComparator();
        sortedKeys.sort((o1, o2) -> {
            ECKey key1 = getChildKeyForExtendedPubKey(o1);
            ECKey key2 = getChildKeyForExtendedPubKey(o2);
            return lexicographicByteArrayComparator.compare(key1.getPubKey(), key2.getPubKey());
        });

        return sortedKeys;
    }

    private ECKey getChildKeyForExtendedPubKey(ExtendedKey extendedKey) {
        if(mapChildrenDerivations.get(extendedKey) == null) {
            return extendedKey.getKey();
        }

        List<ChildNumber> derivation = getDerivations(mapChildrenDerivations.get(extendedKey)).get(0);
        derivation.add(0, extendedKey.getKeyChildNumber());
        return extendedKey.getKey(derivation);
    }

    private List<List<ChildNumber>> getDerivations(String childDerivation) {
        Matcher matcher = MULTIPATH_PATTERN.matcher(childDerivation);
        if(matcher.find()) {
            String multipath = matcher.group(1);
            String[] paths = multipath.split(";");
            List<List<ChildNumber>> derivations = new ArrayList<>();
            for(String path : paths) {
                derivations.add(KeyDerivation.parsePath(childDerivation.replace(matcher.group(), path)));
            }
            return derivations;
        } else {
            return List.of(KeyDerivation.parsePath(childDerivation));
        }
    }

    private String toString(ExtendedKey pubKey, boolean addKeyOrigin, boolean addKey) {
        KeyDerivation keyDerivation = extendedPublicKeys.get(pubKey);
        String childDerivation = mapChildrenDerivations.get(pubKey);
        return writeKey(pubKey, keyDerivation, childDerivation, addKeyOrigin, addKey);
    }

    public static String writeKey(SilentPaymentScanAddress spScanAddress, KeyDerivation keyDerivation, boolean addKeyOrigin) {
        return writeKey(spScanAddress, keyDerivation, addKeyOrigin, false);
    }

    public static String writeKey(SilentPaymentScanAddress spScanAddress, KeyDerivation keyDerivation, boolean addKeyOrigin, boolean useApostrophes) {
        StringBuilder keyBuilder = new StringBuilder();
        if(addKeyOrigin && keyDerivation != null && keyDerivation.getMasterFingerprint() != null && keyDerivation.getMasterFingerprint().length() == 8 && Utils.isHex(keyDerivation.getMasterFingerprint())) {
            keyBuilder.append("[");
            keyBuilder.append(keyDerivation.getMasterFingerprint());
            if(!keyDerivation.getDerivation().isEmpty()) {
                keyBuilder.append(KeyDerivation.writePath(keyDerivation.getDerivation(), useApostrophes).substring(1));
            }
            keyBuilder.append("]");
        }
        keyBuilder.append(spScanAddress.toKeyString());

        return keyBuilder.toString();
    }

    public static String writeKey(ECKey ecKey, KeyDerivation keyDerivation, boolean addKeyOrigin) {
        return writeKey(ecKey, keyDerivation, addKeyOrigin, false);
    }

    public static String writeKey(ECKey ecKey, KeyDerivation keyDerivation, boolean addKeyOrigin, boolean useApostrophes) {
        StringBuilder keyBuilder = new StringBuilder();
        if(addKeyOrigin && keyDerivation != null && keyDerivation.getMasterFingerprint() != null && keyDerivation.getMasterFingerprint().length() == 8 && Utils.isHex(keyDerivation.getMasterFingerprint())) {
            keyBuilder.append("[");
            keyBuilder.append(keyDerivation.getMasterFingerprint());
            if(!keyDerivation.getDerivation().isEmpty()) {
                keyBuilder.append(KeyDerivation.writePath(keyDerivation.getDerivation(), useApostrophes).substring(1));
            }
            keyBuilder.append("]");
        }
        keyBuilder.append(ecKey.hasPrivKey() ? ecKey.getPrivateKeyEncoded().toString() : Utils.bytesToHex(ecKey.getPubKey()));

        return keyBuilder.toString();
    }

    public static String writeKey(ExtendedKey pubKey, KeyDerivation keyDerivation, String childDerivation, boolean addKeyOrigin, boolean addKey) {
        return writeKey(pubKey, keyDerivation, childDerivation, addKeyOrigin, addKey, false);
    }

    public static String writeKey(ExtendedKey pubKey, KeyDerivation keyDerivation, String childDerivation, boolean addKeyOrigin, boolean addKey, boolean useApostrophes) {
        StringBuilder keyBuilder = new StringBuilder();
        if(keyDerivation != null && keyDerivation.getMasterFingerprint() != null && keyDerivation.getMasterFingerprint().length() == 8 && Utils.isHex(keyDerivation.getMasterFingerprint()) && addKeyOrigin) {
            keyBuilder.append("[");
            keyBuilder.append(keyDerivation.getMasterFingerprint());
            if(!keyDerivation.getDerivation().isEmpty()) {
                String path = KeyDerivation.writePath(KeyDerivation.parsePath(keyDerivation.getDerivationPath()), useApostrophes).substring(1);
                keyBuilder.append(path);
            }
            keyBuilder.append("]");
        }

        if(addKey) {
            if(pubKey != null) {
                keyBuilder.append(pubKey.toString());
            }

            if(childDerivation != null) {
                if(!childDerivation.startsWith("/")) {
                    keyBuilder.append("/");
                }

                keyBuilder.append(childDerivation);
            }
        }

        return keyBuilder.toString();
    }

    @Override
    public final boolean equals(Object o) {
        if(this == o) {
            return true;
        }
        if(!(o instanceof OutputDescriptor that)) {
            return false;
        }

        return toString().equals(that.toString());
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    public OutputDescriptor copy(boolean includeChildDerivations) {
        if(isSilentPayments()) {
            return new OutputDescriptor(new LinkedHashMap<>(silentPaymentScanAddresses), new LinkedHashMap<>(mapSilentPaymentLabels), new LinkedHashMap<>(annotations));
        }

        Map<ExtendedKey, KeyDerivation> copyExtendedPublicKeys = new LinkedHashMap<>(extendedPublicKeys);
        Map<ExtendedKey, String> copyChildDerivations = new LinkedHashMap<>(mapChildrenDerivations);
        Map<ExtendedKey, String> copyExtendedPublicKeyLabels = new LinkedHashMap<>(mapExtendedPublicKeyLabels);
        Map<ExtendedKey, ExtendedKey> copyExtendedMasterPrivateKeys = new LinkedHashMap<>(extendedMasterPrivateKeys);
        Map<String, Integer> copyAnnotations = new LinkedHashMap<>(annotations);

        if(!includeChildDerivations) {
            //Ensure consistent xpub order by sorting on the first receive address
            Map<ExtendedKey, String> childDerivations = copyExtendedPublicKeys.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, _ -> "/0/0"));
            OutputDescriptor copyFirstReceive = new OutputDescriptor(scriptType, multisigThreshold, copyExtendedPublicKeys, childDerivations);
            OutputDescriptor copySortedXpubs = OutputDescriptor.getOutputDescriptor(copyFirstReceive.toString());

            return new OutputDescriptor(scriptType, multisigThreshold, copySortedXpubs.extendedPublicKeys, Collections.emptyMap(), copyExtendedPublicKeyLabels, copyExtendedMasterPrivateKeys, copyAnnotations);
        }

        return new OutputDescriptor(scriptType, multisigThreshold, copyExtendedPublicKeys, copyChildDerivations, copyExtendedPublicKeyLabels, copyExtendedMasterPrivateKeys, copyAnnotations);
    }
}
