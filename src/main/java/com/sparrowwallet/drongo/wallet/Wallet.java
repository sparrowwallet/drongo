package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.bip47.PaymentCode;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTOutput;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.sparrowwallet.drongo.protocol.ScriptType.*;
import static com.sparrowwallet.drongo.protocol.Transaction.WITNESS_SCALE_FACTOR;

public class Wallet extends Persistable implements Comparable<Wallet> {
    public static final int DEFAULT_LOOKAHEAD = 20;
    public static final int SEARCH_LOOKAHEAD = 4000;
    public static final String ALLOW_DERIVATIONS_MATCHING_OTHER_SCRIPT_TYPES_PROPERTY = "com.sparrowwallet.allowDerivationsMatchingOtherScriptTypes";
    public static final String ALLOW_DERIVATIONS_MATCHING_OTHER_NETWORKS_PROPERTY = "com.sparrowwallet.allowDerivationsMatchingOtherNetworks";

    private String name;
    private String label;
    private Wallet masterWallet;
    private List<Wallet> childWallets = new ArrayList<>();
    private Network network = Network.getCanonical();
    private PolicyType policyType;
    private ScriptType scriptType;
    private Policy defaultPolicy;
    private List<Keystore> keystores = new ArrayList<>();
    private final TreeSet<WalletNode> purposeNodes = new TreeSet<>();
    private final Map<Sha256Hash, BlockTransaction> transactions = new HashMap<>();
    private final Map<String, String> detachedLabels = new HashMap<>();
    private WalletConfig walletConfig;
    private MixConfig mixConfig;
    private final Map<Sha256Hash, UtxoMixData> utxoMixes = new HashMap<>();
    private Integer storedBlockHeight;
    private Integer gapLimit;
    private Integer watchLast;
    private Date birthDate;

    public Wallet() {
    }

    public Wallet(String name) {
        this.name = name;
    }

    public Wallet(String name, PolicyType policyType, ScriptType scriptType) {
        this(name, policyType, scriptType, null);
    }

    public Wallet(String name, PolicyType policyType, ScriptType scriptType, Date birthDate) {
        this.name = name;
        this.policyType = policyType;
        this.scriptType = scriptType;
        this.birthDate = birthDate;
        this.keystores = Collections.singletonList(new Keystore());
        this.defaultPolicy = Policy.getPolicy(policyType, scriptType, keystores, null);
    }

    public String getName() {
        return name;
    }

    public String getFullName() {
        if(isMasterWallet()) {
            return childWallets.isEmpty() ? name : name + "-" + (label != null && !label.isEmpty() ? label : getAutomaticName());
        }

        return getMasterWallet().getName() + "-" + getDisplayName();
    }

    public String getFullDisplayName() {
        if(isMasterWallet()) {
            return childWallets.isEmpty() ? name : name + " - " + (label != null && !label.isEmpty() ? label : getAutomaticName());
        }

        return getMasterWallet().getName() + " - " + getDisplayName();
    }

    public String getDisplayName() {
        return label != null && !label.isEmpty() ? label : (isMasterWallet() ? getAutomaticName() : name);
    }

    public String getAutomaticName() {
        int account = getAccountIndex();
        return (account < 1 || account > 9) ? "Deposit" : "Account #" + account;
    }

    public String getMasterName() {
        if(isMasterWallet()) {
            return name;
        }

        return getMasterWallet().getName();
    }

    public Wallet addChildWallet(StandardAccount standardAccount) {
        Wallet childWallet = this.copy();

        if(!isMasterWallet()) {
            throw new IllegalStateException("Cannot add child wallet to existing child wallet");
        }

        if(childWallet.containsMasterPrivateKeys() && childWallet.isEncrypted()) {
            throw new IllegalStateException("Cannot derive child wallet xpub from encrypted wallet");
        }

        childWallet.setId(null);
        childWallet.setName(standardAccount.getName());
        childWallet.setLabel(null);
        childWallet.purposeNodes.clear();
        childWallet.transactions.clear();
        childWallet.detachedLabels.clear();
        childWallet.childWallets.clear();
        childWallet.storedBlockHeight = null;
        childWallet.gapLimit = standardAccount.getMinimumGapLimit();
        childWallet.birthDate = null;

        if(standardAccount.getRequiredScriptType() != null) {
            childWallet.setScriptType(standardAccount.getRequiredScriptType());
        }

        for(Keystore keystore : childWallet.getKeystores()) {
            List<ChildNumber> derivation = standardAccount.getRequiredScriptType() != null ? standardAccount.getRequiredScriptType().getDefaultDerivation() : keystore.getKeyDerivation().getDerivation();
            List<ChildNumber> childDerivation;
            if(childWallet.getScriptType().getAccount(KeyDerivation.writePath(derivation)) > -1) {
                childDerivation = childWallet.getScriptType().getDefaultDerivation(standardAccount.getChildNumber().num());
            } else {
                childDerivation = derivation.isEmpty() ? new ArrayList<>() : new ArrayList<>(derivation.subList(0, derivation.size() - 1));
                childDerivation.add(standardAccount.getChildNumber());
            }

            if(keystore.hasMasterPrivateKey()) {
                try {
                    Keystore derivedKeystore = keystore.hasSeed() ? Keystore.fromSeed(keystore.getSeed(), childDerivation) : Keystore.fromMasterPrivateExtendedKey(keystore.getMasterPrivateExtendedKey(), childDerivation);
                    keystore.setKeyDerivation(derivedKeystore.getKeyDerivation());
                    keystore.setExtendedPublicKey(derivedKeystore.getExtendedPublicKey());
                } catch(Exception e) {
                    throw new IllegalStateException("Cannot derive keystore for " + standardAccount + " account", e);
                }
            } else {
                keystore.setKeyDerivation(new KeyDerivation(null, KeyDerivation.writePath(childDerivation)));
                keystore.setExtendedPublicKey(null);
            }
        }

        childWallet.setMasterWallet(this);
        getChildWallets().add(childWallet);
        return childWallet;
    }

    public Wallet getChildWallet(StandardAccount account) {
        for(Wallet childWallet : getChildWallets()) {
            if(!childWallet.isNested()) {
                for(Keystore keystore : childWallet.getKeystores()) {
                    if(keystore.getKeyDerivation().getDerivation().get(keystore.getKeyDerivation().getDerivation().size() - 1).equals(account.getChildNumber())) {
                        return childWallet;
                    }
                }
            }
        }

        return null;
    }

    public Wallet addChildWallet(PaymentCode externalPaymentCode, ScriptType childScriptType, BlockTransactionHashIndex notificationOutput, BlockTransaction notificationTransaction, String label) {
        Wallet bip47Wallet = addChildWallet(externalPaymentCode, childScriptType, label);
        WalletNode notificationNode = bip47Wallet.getNode(KeyPurpose.NOTIFICATION);
        notificationNode.getTransactionOutputs().add(notificationOutput);
        bip47Wallet.updateTransactions(Map.of(notificationTransaction.getHash(), notificationTransaction));

        return bip47Wallet;
    }

    public Wallet addChildWallet(PaymentCode externalPaymentCode, ScriptType childScriptType, String label) {
        if(policyType != PolicyType.SINGLE) {
            throw new IllegalStateException("Cannot add payment code wallet to " + policyType.getName() + " wallet");
        }

        if(!PaymentCode.SEGWIT_SCRIPT_TYPES.contains(scriptType)) {
            throw new IllegalStateException("Cannot add payment code wallet to " + scriptType.getName() + " wallet");
        }

        Keystore masterKeystore = getKeystores().get(0);
        if(masterKeystore.getBip47ExtendedPrivateKey() == null) {
            throw new IllegalStateException("Cannot add payment code wallet, BIP47 extended private key not present");
        }

        Wallet childWallet = new Wallet(childScriptType + "-" + externalPaymentCode.toString());
        childWallet.setLabel(label);
        childWallet.setPolicyType(PolicyType.SINGLE);
        childWallet.setScriptType(childScriptType);
        childWallet.setGapLimit(5);

        Keystore keystore = new Keystore("BIP47");
        keystore.setSource(KeystoreSource.SW_PAYMENT_CODE);
        keystore.setWalletModel(WalletModel.SPARROW);
        List<ChildNumber> derivation = KeyDerivation.getBip47Derivation(getAccountIndex());
        keystore.setKeyDerivation(new KeyDerivation(masterKeystore.getKeyDerivation().getMasterFingerprint(), derivation));
        keystore.setExternalPaymentCode(externalPaymentCode);
        keystore.setBip47ExtendedPrivateKey(masterKeystore.getBip47ExtendedPrivateKey());
        DeterministicKey pubKey = keystore.getBip47ExtendedPrivateKey().getKey().dropPrivateBytes().dropParent();
        keystore.setExtendedPublicKey(new ExtendedKey(pubKey, keystore.getBip47ExtendedPrivateKey().getParentFingerprint(), derivation.get(derivation.size() - 1)));

        childWallet.getKeystores().add(keystore);
        childWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, scriptType, childWallet.getKeystores(), 1));

        childWallet.setMasterWallet(this);
        getChildWallets().add(childWallet);
        return childWallet;
    }

    public Wallet getChildWallet(PaymentCode externalPaymentCode, ScriptType childScriptType) {
        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.getKeystores().size() == 1 && externalPaymentCode != null && childWallet.getScriptType() == childScriptType &&
                    childWallet.getKeystores().get(0).getExternalPaymentCode() != null &&
                    (externalPaymentCode.equals(childWallet.getKeystores().get(0).getExternalPaymentCode()) ||
                            externalPaymentCode.getNotificationAddress().equals(childWallet.getKeystores().get(0).getExternalPaymentCode().getNotificationAddress()))) {
                return childWallet;
            }
        }

        return null;
    }

    public List<Wallet> getAllWallets() {
        List<Wallet> allWallets = new ArrayList<>();
        Wallet masterWallet = isMasterWallet() ? this : getMasterWallet();
        allWallets.add(masterWallet);
        for(Wallet childWallet : getChildWallets()) {
            if(!childWallet.isNested()) {
                allWallets.add(childWallet);
            }
        }

        return allWallets;
    }

    public boolean hasPaymentCode() {
        return getKeystores().size() == 1 && getKeystores().get(0).getBip47ExtendedPrivateKey() != null && policyType == PolicyType.SINGLE
                && PaymentCode.SEGWIT_SCRIPT_TYPES.contains(scriptType);
    }

    public PaymentCode getPaymentCode() {
        if(hasPaymentCode()) {
            return getKeystores().get(0).getPaymentCode();
        }

        return null;
    }

    public Wallet getNotificationWallet() {
        if(isMasterWallet() && hasPaymentCode()) {
            Wallet notificationWallet = new Wallet();
            notificationWallet.setPolicyType(PolicyType.SINGLE);
            notificationWallet.setScriptType(ScriptType.P2PKH);
            notificationWallet.setGapLimit(0);

            Keystore masterKeystore = getKeystores().get(0);

            Keystore keystore = new Keystore();
            keystore.setSource(KeystoreSource.SW_WATCH);
            keystore.setWalletModel(WalletModel.SPARROW);
            keystore.setKeyDerivation(new KeyDerivation(masterKeystore.getKeyDerivation().getMasterFingerprint(), KeyDerivation.getBip47Derivation(getAccountIndex())));
            keystore.setExtendedPublicKey(masterKeystore.getBip47ExtendedPrivateKey());
            keystore.setBip47ExtendedPrivateKey(masterKeystore.getBip47ExtendedPrivateKey());

            notificationWallet.getKeystores().add(keystore);
            notificationWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2PKH, notificationWallet.getKeystores(), 1));

            return notificationWallet;
        }

        return null;
    }

    public Map<BlockTransaction, WalletNode> getNotificationTransaction(PaymentCode externalPaymentCode) {
        Address notificationAddress = externalPaymentCode.getNotificationAddress();
        for(Map.Entry<BlockTransactionHashIndex, WalletNode> txoEntry : getWalletTxos().entrySet()) {
            if(txoEntry.getKey().isSpent()) {
                BlockTransaction blockTransaction = getWalletTransaction(txoEntry.getKey().getSpentBy().getHash());
                if(blockTransaction != null) {
                    TransactionInput txInput0 = blockTransaction.getTransaction().getInputs().get(0);
                    for(TransactionOutput txOutput : blockTransaction.getTransaction().getOutputs()) {
                        if(notificationAddress.equals(txOutput.getScript().getToAddress())
                                && txoEntry.getValue().getTransactionOutputs().stream().anyMatch(ref -> ref.getHash().equals(txInput0.getOutpoint().getHash()) && ref.getIndex() == txInput0.getOutpoint().getIndex())) {
                            try {
                                PaymentCode.getOpReturnData(blockTransaction.getTransaction());
                                return Map.of(blockTransaction, txoEntry.getValue());
                            } catch(Exception e) {
                                //ignore
                            }
                        }
                    }
                }
            }
        }

        return Collections.emptyMap();
    }

    public boolean isNested() {
        return isBip47();
    }

    public boolean isBip47() {
        return !isMasterWallet() && getKeystores().size() == 1 && getKeystores().get(0).getSource() == KeystoreSource.SW_PAYMENT_CODE;
    }

    public StandardAccount getStandardAccountType() {
        int accountIndex = getAccountIndex();
        return Arrays.stream(StandardAccount.values()).filter(standardAccount -> standardAccount.getChildNumber().num() == accountIndex).findFirst().orElse(null);
    }

    public int getAccountIndex() {
        int index = -1;

        for(Keystore keystore : getKeystores()) {
            if(keystore.getKeyDerivation() != null) {
                int keystoreAccount = getScriptType().getAccount(keystore.getKeyDerivation().getDerivationPath());
                if(keystoreAccount != -1 && (index == -1 || keystoreAccount == index)) {
                    index = keystoreAccount;
                } else if(!keystore.getKeyDerivation().getDerivation().isEmpty()) {
                    keystoreAccount = keystore.getKeyDerivation().getDerivation().get(keystore.getKeyDerivation().getDerivation().size() - 1).num();
                    if(index == -1 || keystoreAccount == index) {
                        index = keystoreAccount;
                    }
                }
            }
        }

        return index;
    }

    public boolean isWhirlpoolMasterWallet() {
        if(!isMasterWallet()) {
            return false;
        }

        Set<StandardAccount> whirlpoolAccounts = new HashSet<>(Set.of(StandardAccount.WHIRLPOOL_PREMIX, StandardAccount.WHIRLPOOL_POSTMIX, StandardAccount.WHIRLPOOL_BADBANK));
        for(Wallet childWallet : getChildWallets()) {
            if(!childWallet.isNested()) {
                whirlpoolAccounts.remove(childWallet.getStandardAccountType());
            }
        }

        return whirlpoolAccounts.isEmpty();
    }

    public boolean isWhirlpoolChildWallet() {
        return !isMasterWallet() && getStandardAccountType() != null && StandardAccount.isWhirlpoolAccount(getStandardAccountType());
    }

    public boolean isWhirlpoolMixWallet() {
        return !isMasterWallet() && getMasterWallet().isWhirlpoolMasterWallet() && StandardAccount.isWhirlpoolMixAccount(getStandardAccountType());
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public Network getNetwork() {
        return network;
    }

    public void setNetwork(Network network) {
        this.network = network;
    }

    public PolicyType getPolicyType() {
        return policyType;
    }

    public void setPolicyType(PolicyType policyType) {
        this.policyType = policyType;
    }

    public ScriptType getScriptType() {
        return scriptType;
    }

    public void setScriptType(ScriptType scriptType) {
        this.scriptType = scriptType;
    }

    public Policy getDefaultPolicy() {
        return defaultPolicy;
    }

    public void setDefaultPolicy(Policy defaultPolicy) {
        this.defaultPolicy = defaultPolicy;
    }

    public List<Keystore> getKeystores() {
        return keystores;
    }

    public Map<Sha256Hash, BlockTransaction> getTransactions() {
        return Collections.unmodifiableMap(transactions);
    }

    public synchronized void updateTransactions(Map<Sha256Hash, BlockTransaction> updatedTransactions) {
        for(BlockTransaction blockTx : updatedTransactions.values()) {
            if(!transactions.isEmpty()) {
                Optional<String> optionalLabel = transactions.values().stream().filter(oldBlTx -> oldBlTx.getHash().equals(blockTx.getHash())).map(BlockTransaction::getLabel).filter(Objects::nonNull).findFirst();
                optionalLabel.ifPresent(blockTx::setLabel);
            }

            if(!detachedLabels.isEmpty()) {
                String label = detachedLabels.remove(blockTx.getHashAsString());
                if(label != null && (blockTx.getLabel() == null || blockTx.getLabel().isEmpty())) {
                    blockTx.setLabel(label);
                }
            }
        }

        transactions.putAll(updatedTransactions);

        if(!transactions.isEmpty()) {
            birthDate = transactions.values().stream().map(BlockTransactionHash::getDate).filter(Objects::nonNull).min(Date::compareTo).orElse(birthDate);
        }
    }

    public Map<String, String> getDetachedLabels() {
        return detachedLabels;
    }

    public WalletConfig getWalletConfig() {
        return walletConfig;
    }

    public WalletConfig getMasterWalletConfig() {
        if(!isMasterWallet()) {
            return getMasterWallet().getMasterWalletConfig();
        }

        if(walletConfig == null) {
            walletConfig = new WalletConfig();
        }

        return walletConfig;
    }

    public void setWalletConfig(WalletConfig walletConfig) {
        this.walletConfig = walletConfig;
    }

    public MixConfig getMixConfig() {
        return mixConfig;
    }

    public MixConfig getMasterMixConfig() {
        if(!isMasterWallet()) {
            return getMasterWallet().getMasterMixConfig();
        }

        if(mixConfig == null) {
            mixConfig = new MixConfig();
        }

        return mixConfig;
    }

    public void setMixConfig(MixConfig mixConfig) {
        this.mixConfig = mixConfig;
    }

    public UtxoMixData getUtxoMixData(BlockTransactionHashIndex utxo) {
        return getUtxoMixData(Sha256Hash.of(utxo.toString().getBytes(StandardCharsets.UTF_8)));
    }

    public UtxoMixData getUtxoMixData(Sha256Hash utxoKey) {
        return utxoMixes.get(utxoKey);
    }

    public Map<Sha256Hash, UtxoMixData> getUtxoMixes() {
        return utxoMixes;
    }

    public Integer getStoredBlockHeight() {
        return storedBlockHeight;
    }

    public void setStoredBlockHeight(Integer storedBlockHeight) {
        this.storedBlockHeight = storedBlockHeight;
    }

    public Integer gapLimit() {
        return gapLimit;
    }

    public int getGapLimit() {
        return gapLimit == null ? DEFAULT_LOOKAHEAD : gapLimit;
    }

    public void gapLimit(Integer gapLimit) {
        this.gapLimit = gapLimit;
    }

    public void setGapLimit(int gapLimit) {
        this.gapLimit = gapLimit;
    }

    public Integer getWatchLast() {
        return watchLast;
    }

    public void setWatchLast(Integer watchLast) {
        this.watchLast = watchLast;
    }

    public Date getBirthDate() {
        return birthDate;
    }

    public void setBirthDate(Date birthDate) {
        this.birthDate = birthDate;
    }

    public boolean isMasterWallet() {
        return masterWallet == null;
    }

    public Wallet getMasterWallet() {
        return masterWallet;
    }

    public void setMasterWallet(Wallet masterWallet) {
        this.masterWallet = masterWallet;
    }

    public Wallet getChildWallet(String name) {
        return childWallets.stream().filter(wallet -> wallet.getName().equals(name)).findFirst().orElse(null);
    }

    public List<Wallet> getChildWallets() {
        return childWallets;
    }

    public void setChildWallets(List<Wallet> childWallets) {
        this.childWallets = childWallets;
    }

    public TreeSet<WalletNode> getPurposeNodes() {
        return purposeNodes;
    }

    public synchronized WalletNode getNode(KeyPurpose keyPurpose) {
        WalletNode purposeNode;
        Optional<WalletNode> optionalPurposeNode = purposeNodes.stream().filter(node -> node.getKeyPurpose().equals(keyPurpose)).findFirst();
        if(optionalPurposeNode.isEmpty()) {
            purposeNode = new WalletNode(this, keyPurpose);
            purposeNodes.add(purposeNode);
        } else {
            purposeNode = optionalPurposeNode.get();
        }

        purposeNode.fillToIndex(this, getLookAheadIndex(purposeNode));
        return purposeNode;
    }

    public int getLookAheadIndex(WalletNode node) {
        int lookAheadIndex = getGapLimit() - 1;
        Integer highestUsed = node.getHighestUsedIndex();
        if(highestUsed != null) {
            lookAheadIndex = highestUsed + getGapLimit();
        }

        return lookAheadIndex;
    }

    public WalletNode getFreshNode(KeyPurpose keyPurpose) {
        return getFreshNode(keyPurpose, null);
    }

    public WalletNode getFreshNode(KeyPurpose keyPurpose, WalletNode current) {
        int index = 0;

        WalletNode node = getNode(keyPurpose);
        Integer highestUsed = node.getHighestUsedIndex();
        if(highestUsed != null) {
            index = highestUsed + 1;
        }

        if(current != null && current.getIndex() >= index) {
            index = current.getIndex() + 1;
        }

        if(index >= node.getChildren().size()) {
            node.fillToIndex(this, index);
        }

        for(WalletNode childNode : node.getChildren()) {
            if(childNode.getIndex() == index) {
                return childNode;
            }
        }

        throw new IllegalStateException("Could not fill nodes to index " + index);
    }

    public ECKey getPubKey(WalletNode node) {
        if(policyType == PolicyType.MULTI) {
            throw new IllegalStateException("Attempting to retrieve a single key for a multisig policy wallet");
        } else if(policyType == PolicyType.CUSTOM) {
            throw new UnsupportedOperationException("Cannot determine a public key for a custom policy");
        }

        Keystore keystore = getKeystores().get(0);
        return keystore.getPubKey(node);
    }

    public List<ECKey> getPubKeys(WalletNode node) {
        if(policyType == PolicyType.SINGLE) {
            throw new IllegalStateException("Attempting to retrieve multiple keys for a singlesig policy wallet");
        } else if(policyType == PolicyType.CUSTOM) {
            throw new UnsupportedOperationException("Cannot determine public keys for a custom policy");
        }

        return getKeystores().stream().map(keystore -> keystore.getPubKey(node)).collect(Collectors.toList());
    }

    public Address getAddress(WalletNode node) {
        if(policyType == PolicyType.SINGLE) {
            ECKey pubKey = node.getPubKey();
            return scriptType.getAddress(pubKey);
        } else if(policyType == PolicyType.MULTI) {
            List<ECKey> pubKeys = node.getPubKeys();
            Script script = ScriptType.MULTISIG.getOutputScript(defaultPolicy.getNumSignaturesRequired(), pubKeys);
            return scriptType.getAddress(script);
        } else {
            throw new UnsupportedOperationException("Cannot determine addresses for custom policies");
        }
    }

    public Script getOutputScript(WalletNode node) {
        if(policyType == PolicyType.SINGLE) {
            ECKey pubKey = node.getPubKey();
            return scriptType.getOutputScript(pubKey);
        } else if(policyType == PolicyType.MULTI) {
            List<ECKey> pubKeys = node.getPubKeys();
            Script script = ScriptType.MULTISIG.getOutputScript(defaultPolicy.getNumSignaturesRequired(), pubKeys);
            return scriptType.getOutputScript(script);
        } else {
            throw new UnsupportedOperationException("Cannot determine output script for custom policies");
        }
    }

    public String getOutputDescriptor(WalletNode node) {
        if(policyType == PolicyType.SINGLE) {
            ECKey pubKey = node.getPubKey();
            return scriptType.getOutputDescriptor(pubKey);
        } else if(policyType == PolicyType.MULTI) {
            List<ECKey> pubKeys = node.getPubKeys();
            Script script = ScriptType.MULTISIG.getOutputScript(defaultPolicy.getNumSignaturesRequired(), pubKeys);
            return scriptType.getOutputDescriptor(script);
        } else {
            throw new UnsupportedOperationException("Cannot determine output descriptor for custom policies");
        }
    }

    public List<KeyPurpose> getWalletKeyPurposes() {
        return isBip47() ? List.of(KeyPurpose.RECEIVE) : KeyPurpose.DEFAULT_PURPOSES;
    }

    public KeyPurpose getChangeKeyPurpose() {
        return isBip47() ? KeyPurpose.RECEIVE : KeyPurpose.CHANGE;
    }

    public Map<WalletNode, Set<BlockTransactionHashIndex>> getWalletNodes() {
        Map<WalletNode, Set<BlockTransactionHashIndex>> walletNodes = new LinkedHashMap<>();
        for(KeyPurpose keyPurpose : KeyPurpose.DEFAULT_PURPOSES) {
            getNode(keyPurpose).getChildren().forEach(childNode -> walletNodes.put(childNode, childNode.getTransactionOutputs()));
        }

        return walletNodes;
    }

    public boolean isWalletAddress(Address address) {
        return getWalletAddresses().containsKey(address);
    }

    public Map<Address, WalletNode> getWalletAddresses() {
        Map<Address, WalletNode> walletAddresses = new LinkedHashMap<>();
        for(KeyPurpose keyPurpose : getWalletKeyPurposes()) {
            getWalletAddresses(walletAddresses, getNode(keyPurpose));
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                for(KeyPurpose keyPurpose : childWallet.getWalletKeyPurposes()) {
                    getWalletAddresses(walletAddresses, childWallet.getNode(keyPurpose));
                }
            }
        }

        return walletAddresses;
    }

    private void getWalletAddresses(Map<Address, WalletNode> walletAddresses, WalletNode purposeNode) {
        for(WalletNode addressNode : purposeNode.getChildren()) {
            walletAddresses.put(addressNode.getAddress(), addressNode);
        }
    }

    public boolean isWalletOutputScript(Script outputScript) {
        return getWalletOutputScripts().containsKey(outputScript);
    }

    public Map<Script, WalletNode> getWalletOutputScripts() {
        return getWalletOutputScripts(getWalletKeyPurposes());
    }

    public Map<Script, WalletNode> getWalletOutputScripts(KeyPurpose keyPurpose) {
        if(!getWalletKeyPurposes().contains(keyPurpose)) {
            return Collections.emptyMap();
        }

        return getWalletOutputScripts(List.of(keyPurpose));
    }

    private Map<Script, WalletNode> getWalletOutputScripts(List<KeyPurpose> keyPurposes) {
        Map<Script, WalletNode> walletOutputScripts = new LinkedHashMap<>();
        for(KeyPurpose keyPurpose : keyPurposes) {
            getWalletOutputScripts(walletOutputScripts, getNode(keyPurpose));
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                for(KeyPurpose keyPurpose : childWallet.getWalletKeyPurposes()) {
                    if(keyPurposes.contains(keyPurpose)) {
                        getWalletOutputScripts(walletOutputScripts, childWallet.getNode(keyPurpose));
                    }
                }
            }
        }

        return walletOutputScripts;
    }

    private void getWalletOutputScripts(Map<Script, WalletNode> walletOutputScripts, WalletNode purposeNode) {
        for(WalletNode addressNode : purposeNode.getChildren()) {
            walletOutputScripts.put(addressNode.getOutputScript(), addressNode);
        }
    }

    public boolean isWalletTxo(TransactionInput txInput) {
        return getWalletTxos().keySet().stream().anyMatch(ref -> ref.getHash().equals(txInput.getOutpoint().getHash()) && ref.getIndex() == txInput.getOutpoint().getIndex());
    }

    public boolean isWalletTxo(TransactionOutput txOutput) {
        return getWalletTxos().keySet().stream().anyMatch(ref -> ref.getHash().equals(txOutput.getHash()) && ref.getIndex() == txOutput.getIndex());
    }

    public boolean isWalletTxo(BlockTransactionHashIndex txo) {
        return getWalletTxos().containsKey(txo);
    }

    public Map<BlockTransactionHashIndex, WalletNode> getWalletTxos() {
        Map<BlockTransactionHashIndex, WalletNode> walletTxos = new TreeMap<>();
        for(KeyPurpose keyPurpose : getWalletKeyPurposes()) {
            getWalletTxos(walletTxos, getNode(keyPurpose));
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                for(KeyPurpose keyPurpose : childWallet.getWalletKeyPurposes()) {
                    getWalletTxos(walletTxos, childWallet.getNode(keyPurpose));
                }
            }
        }

        return walletTxos;
    }

    private void getWalletTxos(Map<BlockTransactionHashIndex, WalletNode> walletTxos, WalletNode purposeNode) {
        for(WalletNode addressNode : purposeNode.getChildren()) {
            for(BlockTransactionHashIndex txo : addressNode.getTransactionOutputs()) {
                walletTxos.put(txo, addressNode);
            }
        }
    }

    public Map<BlockTransactionHashIndex, WalletNode> getWalletUtxos() {
        return getWalletTxos(List.of(new SpentTxoFilter()));
    }

    public Map<BlockTransactionHashIndex, WalletNode> getSpendableUtxos() {
        return getWalletTxos(List.of(new SpentTxoFilter(), new FrozenTxoFilter(), new CoinbaseTxoFilter(this)));
    }

    public Map<BlockTransactionHashIndex, WalletNode> getSpendableUtxos(BlockTransaction replacedTransaction) {
        return getWalletTxos(List.of(new SpentTxoFilter(replacedTransaction == null ? null : replacedTransaction.getHash()), new FrozenTxoFilter(), new CoinbaseTxoFilter(this)));
    }

    public Map<BlockTransactionHashIndex, WalletNode> getWalletTxos(Collection<TxoFilter> txoFilters) {
        Map<BlockTransactionHashIndex, WalletNode> walletTxos = new TreeMap<>();
        for(KeyPurpose keyPurpose : getWalletKeyPurposes()) {
            getWalletTxos(walletTxos, getNode(keyPurpose), txoFilters);
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                for(KeyPurpose keyPurpose : childWallet.getWalletKeyPurposes()) {
                    getWalletTxos(walletTxos, childWallet.getNode(keyPurpose), txoFilters);
                }
            }
        }

        return walletTxos;
    }

    private void getWalletTxos(Map<BlockTransactionHashIndex, WalletNode> walletTxos, WalletNode purposeNode, Collection<TxoFilter> txoFilters) {
        for(WalletNode addressNode : purposeNode.getChildren()) {
            for(BlockTransactionHashIndex utxo : addressNode.getTransactionOutputs(txoFilters)) {
                walletTxos.put(utxo, addressNode);
            }
        }
    }

    public boolean hasTransactions() {
        if(!transactions.isEmpty()) {
            return true;
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                if(!childWallet.transactions.isEmpty()) {
                    return true;
                }
            }
        }

        return false;
    }

    public BlockTransaction getWalletTransaction(Sha256Hash txid) {
        BlockTransaction blockTransaction = transactions.get(txid);
        if(blockTransaction != null) {
            return blockTransaction;
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                blockTransaction = childWallet.transactions.get(txid);
                if(blockTransaction != null) {
                    return blockTransaction;
                }
            }
        }

        return null;
    }

    public Map<Sha256Hash, BlockTransaction> getWalletTransactions() {
        Map<Sha256Hash, BlockTransaction> allTransactions = new HashMap<>(transactions);
        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                allTransactions.putAll(childWallet.transactions);
            }
        }

        return allTransactions;
    }

    /**
     * Determines the dust threshold for creating a new change output in this wallet.
     *
     * @param output The output under consideration
     * @param feeRate The fee rate for the transaction creating the change UTXO
     * @return the minimum viable value than the provided change output must have in order to not be dust
     */
    public long getDustThreshold(TransactionOutput output, Double feeRate) {
        return getFee(output, feeRate, Transaction.DUST_RELAY_TX_FEE);
    }

    /**
     * Determines the minimum incremental fee necessary to pay for added the provided output to a transaction
     * This is done by calculating the sum of multiplying the size of the output at the current fee rate,
     * and the size of the input needed to spend it in future at the long term fee rate
     *
     * @param output The output to be added
     * @param feeRate The transaction's fee rate
     * @param longTermFeeRate The long term minimum fee rate
     * @return The fee that adding this output would add
     */
    public long getFee(TransactionOutput output, Double feeRate, Double longTermFeeRate) {
        //Start with length of output
        int outputVbytes = output.getLength();
        //Add length of spending input (with or without discount depending on script type)
        int inputVbytes = getInputVbytes();

        //Return fee rate in sats/vbyte multiplied by the calculated output and input vByte lengths
        return (long)(feeRate * outputVbytes + longTermFeeRate * inputVbytes);
    }

    /**
     * Determines the fee for a transaction from this wallet that has one output and no inputs
     *
     * @param payments The payment details to create the output to send to
     * @return The determined fee
     */
    public long getNoInputsFee(List<Payment> payments, Double feeRate) {
        return (long)Math.ceil((double)getNoInputsWeightUnits(payments) * feeRate / (double)WITNESS_SCALE_FACTOR);
    }

    /**
     * Determines the weight units for a transaction from this wallet that has one output and no inputs
     *
     * @param payments The payment details to create the output to send to
     * @return The determined weight units
     */
    public int getNoInputsWeightUnits(List<Payment> payments) {
        Transaction transaction = new Transaction();
        if(Arrays.asList(ScriptType.WITNESS_TYPES).contains(getScriptType())) {
            transaction.setSegwitFlag(Transaction.DEFAULT_SEGWIT_FLAG);
        }
        for(Payment payment : payments) {
            transaction.addOutput(payment.getAmount(), payment.getAddress());
        }
        return transaction.getWeightUnits();
    }

    /**
     * Return the number of vBytes required for an input created by this wallet.
     *
     * @return the number of vBytes
     */
    public int getInputVbytes() {
        return (int)Math.ceil((double)getInputWeightUnits() / (double)WITNESS_SCALE_FACTOR);
    }

    /**
     * Return the number of weight units required for an input created by this wallet.
     *
     * @return the number of weight units (WU)
     */
    public int getInputWeightUnits() {
        //Estimate assuming an input spending from the parent receive node - it does not matter this node has no real utxos
        WalletNode receiveNode = new WalletNode(this, KeyPurpose.RECEIVE);

        Transaction transaction = new Transaction();
        TransactionOutput prevTxOut = transaction.addOutput(1L, receiveNode.getAddress());

        TransactionInput txInput = null;
        if(getPolicyType().equals(PolicyType.SINGLE)) {
            ECKey pubKey = receiveNode.getPubKey();
            TransactionSignature signature = TransactionSignature.dummy(getScriptType().getSignatureType());
            txInput = getScriptType().addSpendingInput(transaction, prevTxOut, pubKey, signature);
        } else if(getPolicyType().equals(PolicyType.MULTI)) {
            List<ECKey> pubKeys = receiveNode.getPubKeys();
            int threshold = getDefaultPolicy().getNumSignaturesRequired();
            Map<ECKey, TransactionSignature> pubKeySignatures = new TreeMap<>(new ECKey.LexicographicECKeyComparator());
            for(int i = 0; i < pubKeys.size(); i++) {
                pubKeySignatures.put(pubKeys.get(i), i < threshold ? TransactionSignature.dummy(getScriptType().getSignatureType()) : null);
            }
            txInput = getScriptType().addMultisigSpendingInput(transaction, prevTxOut, threshold, pubKeySignatures);
        }

        assert txInput != null;
        int wu = txInput.getLength() * WITNESS_SCALE_FACTOR;
        if(txInput.hasWitness()) {
            wu += txInput.getWitness().getLength();
        }

        return wu;
    }

    public long getCostOfChange(double feeRate, double longTermFeeRate) {
        WalletNode changeNode = getFreshNode(KeyPurpose.CHANGE);
        TransactionOutput changeOutput = new TransactionOutput(new Transaction(), 1L, changeNode.getOutputScript());
        return getFee(changeOutput, feeRate, longTermFeeRate);
    }

    public WalletTransaction createWalletTransaction(List<UtxoSelector> utxoSelectors, List<TxoFilter> txoFilters, List<Payment> payments, List<byte[]> opReturns, Set<WalletNode> excludedChangeNodes, double feeRate, double longTermFeeRate, Long fee, Integer currentBlockHeight, boolean groupByAddress, boolean includeMempoolOutputs) throws InsufficientFundsException {
        boolean sendMax = payments.stream().anyMatch(Payment::isSendMax);
        long totalPaymentAmount = payments.stream().map(Payment::getAmount).mapToLong(v -> v).sum();
        Map<BlockTransactionHashIndex, WalletNode> availableTxos = getWalletTxos(txoFilters);
        long totalAvailableValue = availableTxos.keySet().stream().mapToLong(BlockTransactionHashIndex::getValue).sum();

        if(fee != null && feeRate != Transaction.DEFAULT_MIN_RELAY_FEE) {
            throw new IllegalArgumentException("Use an input fee rate of 1 sat/vB when using a defined fee amount so UTXO selectors overestimate effective value");
        }

        long maxSpendableAmt = getMaxSpendable(payments.stream().map(Payment::getAddress).collect(Collectors.toList()), feeRate, availableTxos);
        if(maxSpendableAmt < 0) {
            throw new InsufficientFundsException("Not enough combined value in all available UTXOs to send a transaction to the provided addresses at this fee rate");
        }

        //When a user fee is set, we can calculate the fees to spend all UTXOs because we assume all UTXOs are spendable at a fee rate of 1 sat/vB
        //We can then add the user set fee less this amount as a "phantom payment amount" to the value required to find (which cannot include transaction fees)
        long valueRequiredAmt = totalPaymentAmount + (fee != null ? fee - (totalAvailableValue - maxSpendableAmt) : 0);
        if(maxSpendableAmt < valueRequiredAmt) {
            throw new InsufficientFundsException("Not enough combined value in all available UTXOs to send a transaction to send the provided payments at the user set fee" + (fee == null ? " rate" : ""));
        }

        while(true) {
            List<Map<BlockTransactionHashIndex, WalletNode>> selectedUtxoSets = selectInputSets(availableTxos, utxoSelectors, txoFilters, valueRequiredAmt, feeRate, longTermFeeRate, groupByAddress, includeMempoolOutputs, sendMax);
            Map<BlockTransactionHashIndex, WalletNode> selectedUtxos = new LinkedHashMap<>();
            selectedUtxoSets.forEach(selectedUtxos::putAll);
            long totalSelectedAmt = selectedUtxos.keySet().stream().mapToLong(BlockTransactionHashIndex::getValue).sum();
            int numSets = selectedUtxoSets.size();
            List<Payment> txPayments = new ArrayList<>(payments);
            Set<WalletNode> txExcludedChangeNodes = new HashSet<>(excludedChangeNodes);

            Transaction transaction = new Transaction();
            transaction.setVersion(2);
            if(currentBlockHeight != null) {
                transaction.setLocktime(currentBlockHeight.longValue());
            }

            //Add inputs
            for(Map.Entry<BlockTransactionHashIndex, WalletNode> selectedUtxo : selectedUtxos.entrySet()) {
                Transaction prevTx = getWalletTransaction(selectedUtxo.getKey().getHash()).getTransaction();
                TransactionOutput prevTxOut = prevTx.getOutputs().get((int)selectedUtxo.getKey().getIndex());
                TransactionInput txInput = addDummySpendingInput(transaction, selectedUtxo.getValue(), prevTxOut);

                //Enable opt-in RBF by default, matching Bitcoin Core and Electrum
                txInput.setSequenceNumber(TransactionInput.SEQUENCE_RBF_ENABLED);
            }

            if(getScriptType() == P2TR && currentBlockHeight != null) {
                applySequenceAntiFeeSniping(transaction, selectedUtxos, currentBlockHeight);
            }

            for(int i = 1; i < numSets; i+=2) {
                WalletNode mixNode = getFreshNode(getChangeKeyPurpose());
                txExcludedChangeNodes.add(mixNode);
                Payment fakeMixPayment = new Payment(mixNode.getAddress(), ".." + mixNode + " (Fake Mix)", totalPaymentAmount, false);
                fakeMixPayment.setType(Payment.Type.FAKE_MIX);
                txPayments.add(fakeMixPayment);
            }

            //Add recipient outputs
            for(Payment payment : txPayments) {
                transaction.addOutput(payment.getAmount(), payment.getAddress());
            }

            //Add OP_RETURNs
            for(byte[] opReturn : opReturns) {
                transaction.addOutput(0L, new Script(List.of(ScriptChunk.fromOpcode(ScriptOpCodes.OP_RETURN), ScriptChunk.fromData(opReturn))));
            }

            double noChangeVSize = transaction.getVirtualSize();
            long noChangeFeeRequiredAmt = (fee == null ? (long)Math.floor(feeRate * noChangeVSize) : fee);

            //Add 1 satoshi to accommodate longer signatures when feeRate equals default min relay fee to ensure fee is sufficient
            noChangeFeeRequiredAmt = (fee == null && feeRate == Transaction.DEFAULT_MIN_RELAY_FEE ? noChangeFeeRequiredAmt + 1 : noChangeFeeRequiredAmt);

            //If sending all selected utxos, set the recipient amount to equal to total of those utxos less the no change fee
            long maxSendAmt = totalSelectedAmt - noChangeFeeRequiredAmt;

            Optional<Payment> optMaxPayment = payments.stream().filter(Payment::isSendMax).findFirst();
            if(optMaxPayment.isPresent()) {
                Payment maxPayment = optMaxPayment.get();
                maxSendAmt = maxSendAmt - payments.stream().filter(payment -> !maxPayment.equals(payment)).map(Payment::getAmount).mapToLong(v -> v).sum();
                if(maxSendAmt > 0 && maxPayment.getAmount() != maxSendAmt) {
                    maxPayment.setAmount(maxSendAmt);
                    totalPaymentAmount = payments.stream().map(Payment::getAmount).mapToLong(v -> v).sum();
                    continue;
                }
            }

            //Calculate what is left over from selected utxos after paying recipient
            long differenceAmt = totalSelectedAmt - totalPaymentAmount * numSets;

            //If insufficient fee, increase value required from inputs to include the fee and try again
            if(differenceAmt < noChangeFeeRequiredAmt) {
                valueRequiredAmt = totalSelectedAmt + 1;
                //If we haven't selected all UTXOs yet, don't require more than the max spendable amount
                if(valueRequiredAmt > maxSpendableAmt && transaction.getInputs().size() < availableTxos.size()) {
                    valueRequiredAmt = maxSpendableAmt;
                }

                continue;
            }

            //Determine if a change output is required by checking if its value is greater than its dust threshold
            List<Long> setChangeAmts = getSetChangeAmounts(selectedUtxoSets, totalPaymentAmount, noChangeFeeRequiredAmt);
            double noChangeFeeRate = (fee == null ? feeRate : noChangeFeeRequiredAmt / transaction.getVirtualSize());
            long costOfChangeAmt = getCostOfChange(noChangeFeeRate, longTermFeeRate);
            if(setChangeAmts.stream().allMatch(amt -> amt > costOfChangeAmt) || (numSets > 1 && differenceAmt / transaction.getVirtualSize() > noChangeFeeRate * 2)) {
                //Change output is required, determine new fee once change output has been added
                WalletNode changeNode = getFreshNode(getChangeKeyPurpose());
                while(txExcludedChangeNodes.contains(changeNode)) {
                    changeNode = getFreshNode(getChangeKeyPurpose(), changeNode);
                }
                TransactionOutput changeOutput = new TransactionOutput(transaction, setChangeAmts.iterator().next(), changeNode.getOutputScript());
                double changeVSize = noChangeVSize + changeOutput.getLength() * numSets;
                long changeFeeRequiredAmt = (fee == null ? (long)Math.floor(feeRate * changeVSize) : fee);
                changeFeeRequiredAmt = (fee == null && feeRate == Transaction.DEFAULT_MIN_RELAY_FEE ? changeFeeRequiredAmt + 1 : changeFeeRequiredAmt);
                while(changeFeeRequiredAmt % numSets > 0) {
                    changeFeeRequiredAmt++;
                }

                //Add change output(s)
                Map<WalletNode, Long> changeMap = new LinkedHashMap<>();
                setChangeAmts = getSetChangeAmounts(selectedUtxoSets, totalPaymentAmount, changeFeeRequiredAmt);
                for(Long setChangeAmt : setChangeAmts) {
                    transaction.addOutput(setChangeAmt, changeNode.getOutputScript());
                    changeMap.put(changeNode, setChangeAmt);
                    changeNode = getFreshNode(getChangeKeyPurpose(), changeNode);
                }

                if(setChangeAmts.stream().anyMatch(amt -> amt < costOfChangeAmt)) {
                    //The new fee has meant that one of the change outputs is now dust. We pay too high a fee without change, but change is dust when added.
                    if(numSets > 1 && differenceAmt / transaction.getVirtualSize() < noChangeFeeRate * 2) {
                        //Maximize privacy. Pay a higher fee to keep multiple output sets.
                        return new WalletTransaction(this, transaction, utxoSelectors, selectedUtxoSets, txPayments, differenceAmt);
                    } else {
                        //Maxmize efficiency. Increase value required from inputs and try again.
                        valueRequiredAmt = totalSelectedAmt + 1;
                        continue;
                    }
                }

                return new WalletTransaction(this, transaction, utxoSelectors, selectedUtxoSets, txPayments, changeMap, changeFeeRequiredAmt);
            }

            return new WalletTransaction(this, transaction, utxoSelectors, selectedUtxoSets, txPayments, differenceAmt);
        }
    }

    private void applySequenceAntiFeeSniping(Transaction transaction, Map<BlockTransactionHashIndex, WalletNode> selectedUtxos, int currentBlockHeight) {
        Random random = new Random();
        boolean locktime = random.nextInt(2) == 0 || getScriptType() != P2TR || selectedUtxos.keySet().stream().anyMatch(utxo -> utxo.getConfirmations(currentBlockHeight) > 65535);

        if(locktime) {
            transaction.setLocktime(currentBlockHeight);
            if(random.nextInt(10) == 0) {
                transaction.setLocktime(Math.max(0, currentBlockHeight - random.nextInt(100)));
            }
        } else {
            transaction.setLocktime(0);
            int inputIndex = random.nextInt(transaction.getInputs().size());
            TransactionInput txInput = transaction.getInputs().get(inputIndex);
            BlockTransactionHashIndex utxo = selectedUtxos.keySet().stream().filter(ref -> ref.getHash().equals(txInput.getOutpoint().getHash()) && ref.getIndex() == txInput.getOutpoint().getIndex()).findFirst().orElseThrow();
            txInput.setSequenceNumber(utxo.getConfirmations(currentBlockHeight));
            if(random.nextInt(10) == 0) {
                txInput.setSequenceNumber(Math.max(0, txInput.getSequenceNumber() - random.nextInt(100)));
            }
        }
    }

    private List<Long> getSetChangeAmounts(List<Map<BlockTransactionHashIndex, WalletNode>> selectedUtxoSets, long totalPaymentAmount, long feeRequiredAmt) {
        List<Long> changeAmts = new ArrayList<>();
        int numSets = selectedUtxoSets.size();
        for(Map<BlockTransactionHashIndex, WalletNode> selectedUtxoSet : selectedUtxoSets) {
            long setAmt = selectedUtxoSet.keySet().stream().mapToLong(BlockTransactionHashIndex::getValue).sum();
            long setChangeAmt = setAmt - (totalPaymentAmount + feeRequiredAmt / numSets);
            changeAmts.add(setChangeAmt);
        }

        return changeAmts;
    }

    public static TransactionInput addDummySpendingInput(Transaction transaction, WalletNode walletNode, TransactionOutput prevTxOut) {
        Wallet signingWallet = walletNode.getWallet();
        if(signingWallet.getPolicyType().equals(PolicyType.SINGLE)) {
            ECKey pubKey = walletNode.getPubKey();
            return signingWallet.getScriptType().addSpendingInput(transaction, prevTxOut, pubKey, TransactionSignature.dummy(signingWallet.getScriptType().getSignatureType()));
        } else if(signingWallet.getPolicyType().equals(PolicyType.MULTI)) {
            List<ECKey> pubKeys = walletNode.getPubKeys();
            int threshold = signingWallet.getDefaultPolicy().getNumSignaturesRequired();
            Map<ECKey, TransactionSignature> pubKeySignatures = new TreeMap<>(new ECKey.LexicographicECKeyComparator());
            for(int i = 0; i < pubKeys.size(); i++) {
                pubKeySignatures.put(pubKeys.get(i), i < threshold ? TransactionSignature.dummy(signingWallet.getScriptType().getSignatureType()) : null);
            }
            return signingWallet.getScriptType().addMultisigSpendingInput(transaction, prevTxOut, threshold, pubKeySignatures);
        } else {
            throw new UnsupportedOperationException("Cannot create transaction for policy type " + signingWallet.getPolicyType());
        }
    }

    private List<Map<BlockTransactionHashIndex, WalletNode>> selectInputSets(Map<BlockTransactionHashIndex, WalletNode> availableTxos, List<UtxoSelector> utxoSelectors, List<TxoFilter> txoFilters, Long targetValue, double feeRate, double longTermFeeRate, boolean groupByAddress, boolean includeMempoolOutputs, boolean sendMax) throws InsufficientFundsException {
        List<OutputGroup> utxoPool = getGroupedUtxos(txoFilters, feeRate, longTermFeeRate, groupByAddress);

        List<OutputGroup.Filter> filters = new ArrayList<>();
        filters.add(new OutputGroup.Filter(1, 6, false));
        filters.add(new OutputGroup.Filter(1, 1, false));
        if(includeMempoolOutputs) {
            filters.add(new OutputGroup.Filter(0, 0, false));
            filters.add(new OutputGroup.Filter(0, 0, true));
        } else {
            filters.add(new OutputGroup.Filter(1, 1, true));
        }

        if(sendMax) {
            Collections.reverse(filters);
        }

        for(OutputGroup.Filter filter : filters) {
            List<OutputGroup> filteredPool = utxoPool.stream().filter(filter::isEligible).collect(Collectors.toList());

            for(UtxoSelector utxoSelector : utxoSelectors) {
                List<Collection<BlockTransactionHashIndex>> selectedInputSets = utxoSelector.selectSets(targetValue, filteredPool);
                List<Map<BlockTransactionHashIndex, WalletNode>> selectedInputSetsList = new ArrayList<>();
                long total = 0;
                for(Collection<BlockTransactionHashIndex> selectedInputs : selectedInputSets) {
                    total += selectedInputs.stream().mapToLong(BlockTransactionHashIndex::getValue).sum();
                    Map<BlockTransactionHashIndex, WalletNode> selectedInputsMap = new LinkedHashMap<>();
                    List<BlockTransactionHashIndex> shuffledInputs = new ArrayList<>(selectedInputs);
                    if(utxoSelector.shuffleInputs()) {
                        Collections.shuffle(shuffledInputs);
                    }
                    for(BlockTransactionHashIndex shuffledInput : shuffledInputs) {
                        selectedInputsMap.put(shuffledInput, availableTxos.get(shuffledInput));
                    }
                    selectedInputSetsList.add(selectedInputsMap);
                }

                if(total > targetValue * selectedInputSetsList.size()) {
                    return selectedInputSetsList;
                }
            }
        }

        throw new InsufficientFundsException("Not enough combined value in UTXOs for output value " + targetValue, targetValue);
    }

    public List<OutputGroup> getGroupedUtxos(List<TxoFilter> txoFilters, double feeRate, double longTermFeeRate, boolean groupByAddress) {
        List<OutputGroup> outputGroups = new ArrayList<>();
        Map<Sha256Hash, BlockTransaction> walletTransactions = getWalletTransactions();
        Map<BlockTransactionHashIndex, WalletNode> walletTxos = getWalletTxos();
        for(KeyPurpose keyPurpose : getWalletKeyPurposes()) {
            getGroupedUtxos(outputGroups, getNode(keyPurpose), txoFilters, walletTransactions, walletTxos, feeRate, longTermFeeRate, groupByAddress);
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                for(KeyPurpose keyPurpose : childWallet.getWalletKeyPurposes()) {
                    childWallet.getGroupedUtxos(outputGroups, childWallet.getNode(keyPurpose), txoFilters, walletTransactions, walletTxos, feeRate, longTermFeeRate, groupByAddress);
                }
            }
        }

        return outputGroups;
    }

    private void getGroupedUtxos(List<OutputGroup> outputGroups, WalletNode purposeNode, List<TxoFilter> txoFilters, Map<Sha256Hash, BlockTransaction> walletTransactions, Map<BlockTransactionHashIndex, WalletNode> walletTxos, double feeRate, double longTermFeeRate, boolean groupByAddress) {
        int inputWeightUnits = getInputWeightUnits();
        for(WalletNode addressNode : purposeNode.getChildren()) {
            OutputGroup outputGroup = null;
            for(BlockTransactionHashIndex utxo : addressNode.getTransactionOutputs(txoFilters)) {
                if(outputGroup == null || !groupByAddress) {
                    outputGroup = new OutputGroup(addressNode.getWallet().getScriptType(), getStoredBlockHeight(), inputWeightUnits, feeRate, longTermFeeRate);
                    outputGroups.add(outputGroup);
                }

                outputGroup.add(utxo, allInputsFromWallet(walletTransactions, walletTxos, utxo.getHash()), isNotificationChange(walletTransactions, utxo.getHash()));
            }
        }
    }

    /**
     * Determines if the provided wallet transaction was created from a purely internal transaction
     *
     * @param txId The txid
     * @return Whether the transaction was created entirely from inputs that reference outputs that belong to this wallet
     */
    public boolean allInputsFromWallet(Sha256Hash txId) {
        Map<Sha256Hash, BlockTransaction> allTransactions = getWalletTransactions();
        Map<BlockTransactionHashIndex, WalletNode> allTxos = getWalletTxos();
        return allInputsFromWallet(allTransactions, allTxos, txId);
    }

    private boolean allInputsFromWallet(Map<Sha256Hash, BlockTransaction> walletTransactions, Map<BlockTransactionHashIndex, WalletNode> walletTxos, Sha256Hash txId) {
        BlockTransaction utxoBlkTx = walletTransactions.get(txId);
        if(utxoBlkTx == null) {
            //Provided txId was not a wallet transaction
            return false;
        }

        for(int i = 0; i < utxoBlkTx.getTransaction().getInputs().size(); i++) {
            TransactionInput utxoTxInput = utxoBlkTx.getTransaction().getInputs().get(i);
            BlockTransaction prevBlkTx = walletTransactions.get(utxoTxInput.getOutpoint().getHash());
            if(prevBlkTx == null) {
                return false;
            }

            int index = (int)utxoTxInput.getOutpoint().getIndex();
            TransactionOutput prevTxOut = prevBlkTx.getTransaction().getOutputs().get(index);
            BlockTransactionHashIndex spendingTXI = new BlockTransactionHashIndex(utxoBlkTx.getHash(), utxoBlkTx.getHeight(), utxoBlkTx.getDate(), utxoBlkTx.getFee(), i, prevTxOut.getValue());
            BlockTransactionHashIndex spentTXO = new BlockTransactionHashIndex(prevBlkTx.getHash(), prevBlkTx.getHeight(), prevBlkTx.getDate(), prevBlkTx.getFee(), index, prevTxOut.getValue(), spendingTXI);
            if(!walletTxos.containsKey(spentTXO)) {
                return false;
            }
        }

        return true;
    }

    private boolean isNotificationChange(Map<Sha256Hash, BlockTransaction> walletTransactions, Sha256Hash txId) {
        BlockTransaction utxoBlkTx = walletTransactions.get(txId);
        try {
            PaymentCode.getOpReturnData(utxoBlkTx.getTransaction());
            return true;
        } catch(IllegalArgumentException e) {
            //ignore, not a notification tx
        }

        return false;
    }

    /**
     * Determines the maximum total amount this wallet can send for the number and type of addresses at the given fee rate
     *
     * @param paymentAddresses the addresses to sent to (amounts are irrelevant)
     * @param feeRate the fee rate in sats/vB
     * @return the maximum spendable amount (can be negative if the fee is higher than the combined UTXO value)
     */
    public long getMaxSpendable(List<Address> paymentAddresses, double feeRate, Map<BlockTransactionHashIndex, WalletNode> availableTxos) {
        long maxInputValue = 0;

        Map<Wallet, Integer> cachedInputWeightUnits = new HashMap<>();
        Transaction transaction = new Transaction();
        for(Map.Entry<BlockTransactionHashIndex, WalletNode> utxo : availableTxos.entrySet()) {
            int inputWeightUnits = cachedInputWeightUnits.computeIfAbsent(utxo.getValue().getWallet(), Wallet::getInputWeightUnits);
            long minInputValue = (long)Math.ceil(feeRate * inputWeightUnits / WITNESS_SCALE_FACTOR);
            if(utxo.getKey().getValue() > minInputValue) {
                Transaction prevTx = getWalletTransaction(utxo.getKey().getHash()).getTransaction();
                TransactionOutput prevTxOut = prevTx.getOutputs().get((int)utxo.getKey().getIndex());
                addDummySpendingInput(transaction, utxo.getValue(), prevTxOut);
                maxInputValue += utxo.getKey().getValue();
            }
        }

        for(Address address : paymentAddresses) {
            transaction.addOutput(1L, address);
        }

        long fee = (long)Math.floor(transaction.getVirtualSize() * feeRate);
        return maxInputValue - fee;
    }

    public boolean canSign(Transaction transaction) {
        return isValid() && !getSigningNodes(transaction).isEmpty();
    }

    /**
     * Determines which nodes in this wallet can sign which inputs in the provided transaction
     *
     * @param transaction The transaction to be signed, or that has been signed
     * @return A map if the PSBT inputs and the nodes that can sign them
     */
    public Map<TransactionInput, WalletNode> getSigningNodes(Transaction transaction) {
        Map<TransactionInput, WalletNode> signingNodes = new LinkedHashMap<>();
        Map<Script, WalletNode> walletOutputScripts = getWalletOutputScripts();

        for(TransactionInput txInput : transaction.getInputs()) {
            BlockTransaction blockTransaction = getWalletTransaction(txInput.getOutpoint().getHash());
            if(blockTransaction != null && blockTransaction.getTransaction().getOutputs().size() > txInput.getOutpoint().getIndex()) {
                TransactionOutput utxo = blockTransaction.getTransaction().getOutputs().get((int)txInput.getOutpoint().getIndex());

                if(utxo != null) {
                    Script scriptPubKey = utxo.getScript();
                    WalletNode signingNode = walletOutputScripts.get(scriptPubKey);
                    if(signingNode != null) {
                        signingNodes.put(txInput, signingNode);
                    }
                }
            }
        }

        return signingNodes;
    }

    /**
     * Determines which keystores have signed a transaction
     *
     * @param transaction The signed transaction
     * @return A map keyed with the transactionInput mapped to a map of the signatures and associated keystores that signed it
     */
    public Map<TransactionInput, Map<TransactionSignature, Keystore>> getSignedKeystores(Transaction transaction) {
        Map<TransactionInput, WalletNode> signingNodes = getSigningNodes(transaction);
        Map<TransactionInput, Map<TransactionSignature, Keystore>> signedKeystores = new LinkedHashMap<>();

        for(TransactionInput txInput : signingNodes.keySet()) {
            WalletNode walletNode = signingNodes.get(txInput);
            Wallet signingWallet = walletNode.getWallet();
            Map<ECKey, Keystore> keystoreKeysForNode = signingWallet.getKeystores().stream()
                    .collect(Collectors.toMap(keystore -> signingWallet.getScriptType().getOutputKey(keystore.getPubKey(walletNode)), Function.identity(),
                    (u, v) -> { throw new IllegalStateException("Duplicate keys from different keystores for node " + walletNode); },
                    LinkedHashMap::new));

            Map<ECKey, TransactionSignature> keySignatureMap = new LinkedHashMap<>();

            BlockTransaction blockTransaction = signingWallet.transactions.get(txInput.getOutpoint().getHash());
            if(blockTransaction != null && blockTransaction.getTransaction().getOutputs().size() > txInput.getOutpoint().getIndex()) {
                TransactionOutput spentTxo = blockTransaction.getTransaction().getOutputs().get((int)txInput.getOutpoint().getIndex());

                Script signingScript = getSigningScript(txInput, spentTxo);
                Sha256Hash hash;
                if(signingWallet.getScriptType() == P2TR) {
                    List<TransactionOutput> spentOutputs = transaction.getInputs().stream().map(input -> signingWallet.transactions.get(input.getOutpoint().getHash()).getTransaction().getOutputs().get((int)input.getOutpoint().getIndex())).collect(Collectors.toList());
                    hash = transaction.hashForTaprootSignature(spentOutputs, txInput.getIndex(), !P2TR.isScriptType(signingScript), signingScript, SigHash.DEFAULT, null);
                } else if(txInput.hasWitness()) {
                    hash = transaction.hashForWitnessSignature(txInput.getIndex(), signingScript, spentTxo.getValue(), SigHash.ALL);
                } else {
                    hash = transaction.hashForLegacySignature(txInput.getIndex(), signingScript, SigHash.ALL);
                }

                for(ECKey sigPublicKey : keystoreKeysForNode.keySet()) {
                    for(TransactionSignature signature : txInput.hasWitness() ? txInput.getWitness().getSignatures() : txInput.getScriptSig().getSignatures()) {
                        if(sigPublicKey.verify(hash, signature)) {
                            keySignatureMap.put(sigPublicKey, signature);
                        }
                    }
                }

                keystoreKeysForNode.keySet().retainAll(keySignatureMap.keySet());

                Map<TransactionSignature, Keystore> inputSignatureKeystores = new LinkedHashMap<>();
                for(ECKey signingKey : keystoreKeysForNode.keySet()) {
                    inputSignatureKeystores.put(keySignatureMap.get(signingKey), keystoreKeysForNode.get(signingKey));
                }

                signedKeystores.put(txInput, inputSignatureKeystores);
            }
        }

        return signedKeystores;
    }

    private Script getSigningScript(TransactionInput txInput, TransactionOutput spentTxo) {
        Script signingScript = spentTxo.getScript();

        if(P2SH.isScriptType(signingScript)) {
            signingScript = txInput.getScriptSig().getFirstNestedScript();
        }

        if(P2WPKH.isScriptType(signingScript)) {
            signingScript = ScriptType.P2PKH.getOutputScript(signingScript.getPubKeyHash());
        } else if(P2WSH.isScriptType(signingScript) && txInput.hasWitness()) {
            signingScript = txInput.getWitness().getWitnessScript();
        }

        return signingScript;
    }

    public boolean canSign(PSBT psbt) {
        return isValid() && !getSigningNodes(psbt).isEmpty();
    }

    public boolean canSignAllInputs(PSBT psbt) {
        return isValid() && getSigningNodes(psbt).size() == psbt.getPsbtInputs().size();
    }

    /**
     * Determines which nodes in this wallet can sign which inputs in the provided PSBT
     *
     * @param psbt The PSBT to be signed
     * @return A map if the PSBT inputs and the nodes that can sign them
     */
    public Map<PSBTInput, WalletNode> getSigningNodes(PSBT psbt) {
        Map<PSBTInput, WalletNode> signingNodes = new LinkedHashMap<>();
        Map<Script, WalletNode> walletOutputScripts = getWalletOutputScripts();

        for(PSBTInput psbtInput : psbt.getPsbtInputs()) {
            TransactionOutput utxo = psbtInput.getUtxo();

            if(utxo != null) {
                Script scriptPubKey = utxo.getScript();
                WalletNode signingNode = walletOutputScripts.get(scriptPubKey);
                if(signingNode != null) {
                    signingNodes.put(psbtInput, signingNode);
                }
            }
        }

        return signingNodes;
    }

    public Collection<Keystore> getSigningKeystores(PSBT psbt) {
        Set<Keystore> signingKeystores = new LinkedHashSet<>();

        for(Map.Entry<ExtendedKey, KeyDerivation> entry : psbt.getExtendedPublicKeys().entrySet()) {
            for(Keystore keystore : getKeystores()) {
                if(entry.getKey().equals(keystore.getExtendedPublicKey()) && entry.getValue().equals(keystore.getKeyDerivation())) {
                    signingKeystores.add(keystore);
                }
            }
        }

        for(PSBTInput psbtInput : psbt.getPsbtInputs()) {
            for(Map.Entry<ECKey, KeyDerivation> entry : psbtInput.getDerivedPublicKeys().entrySet()) {
                for(Keystore keystore : getKeystores().stream().filter(k -> !signingKeystores.contains(k)).toList()) {
                    ECKey derivedKey = keystore.getPubKeyForDerivation(entry.getValue());
                    if(derivedKey != null && Arrays.equals(entry.getKey().getPubKey(), derivedKey.getPubKey())) {
                        signingKeystores.add(keystore);
                    }
                }
            }
        }

        return signingKeystores;
    }

    public Integer getRequiredGapLimit(PSBT psbt) {
        Wallet copy = this.copy();
        for(KeyPurpose keyPurpose : KeyPurpose.DEFAULT_PURPOSES) {
            WalletNode purposeNode = copy.getNode(keyPurpose);
            purposeNode.fillToIndex(purposeNode.getChildren().size() + SEARCH_LOOKAHEAD);
        }
        Map<PSBTInput, WalletNode> copySigningNodes = copy.getSigningNodes(psbt);
        boolean found = false;
        int gapLimit = getGapLimit();
        for(KeyPurpose keyPurpose : KeyPurpose.DEFAULT_PURPOSES) {
            OptionalInt optHighestIndex = copySigningNodes.values().stream().filter(node -> node.getKeyPurpose() == keyPurpose).mapToInt(WalletNode::getIndex).max();
            if(optHighestIndex.isPresent()) {
                found = true;
                Integer highestUsedIndex = getNode(keyPurpose).getHighestUsedIndex();
                gapLimit = Math.max(gapLimit, optHighestIndex.getAsInt() - (highestUsedIndex == null ? -1 : highestUsedIndex));
            }
        }

        return found ? gapLimit : null;
    }

    /**
     * Determines which keystores have signed a PSBT
     *
     * @param psbt The partially signed or finalized PSBT
     * @return A map keyed with the PSBTInput mapped to a map of the signatures and associated keystores that signed it
     */
    public Map<PSBTInput, Map<TransactionSignature, Keystore>> getSignedKeystores(PSBT psbt) {
        Map<PSBTInput, WalletNode> signingNodes = getSigningNodes(psbt);
        Map<PSBTInput, Map<TransactionSignature, Keystore>> signedKeystores = new LinkedHashMap<>();

        for(PSBTInput psbtInput : signingNodes.keySet()) {
            WalletNode walletNode = signingNodes.get(psbtInput);
            Wallet signingWallet = walletNode.getWallet();
            Map<ECKey, Keystore> keystoreKeysForNode = signingWallet.getKeystores().stream()
                    .collect(Collectors.toMap(keystore -> signingWallet.getScriptType().getOutputKey(keystore.getPubKey(walletNode)), Function.identity(),
                    (u, v) -> { throw new IllegalStateException("Duplicate keys from different keystores for node " + walletNode); },
                    LinkedHashMap::new));

            Map<ECKey, TransactionSignature> keySignatureMap;
            if(psbt.isFinalized() || psbtInput.isTaproot()) {
                keySignatureMap = psbtInput.getSigningKeys(keystoreKeysForNode.keySet());
            } else {
                keySignatureMap = psbtInput.getPartialSignatures();
            }

            keystoreKeysForNode.keySet().retainAll(keySignatureMap.keySet());

            Map<TransactionSignature, Keystore> inputSignatureKeystores = new LinkedHashMap<>();
            for(ECKey signingKey : keystoreKeysForNode.keySet()) {
                inputSignatureKeystores.put(keySignatureMap.get(signingKey), keystoreKeysForNode.get(signingKey));
            }

            signedKeystores.put(psbtInput, inputSignatureKeystores);
        }

        return signedKeystores;
    }

    public void sign(PSBT psbt) throws MnemonicException {
        Map<PSBTInput, WalletNode> signingNodes = getSigningNodes(psbt);
        for(Map.Entry<PSBTInput, WalletNode> signingEntry : signingNodes.entrySet()) {
            Wallet signingWallet = signingEntry.getValue().getWallet();
            for(Keystore keystore : signingWallet.getKeystores()) {
                if(keystore.hasPrivateKey()) {
                    ECKey privKey = signingWallet.getScriptType().getOutputKey(keystore.getKey(signingEntry.getValue()));
                    PSBTInput psbtInput = signingEntry.getKey();

                    if(!psbtInput.isSigned()) {
                        psbtInput.sign(privKey);
                    }
                }
            }
        }
    }

    public void finalise(PSBT psbt) {
        int threshold = getDefaultPolicy().getNumSignaturesRequired();
        Map<PSBTInput, WalletNode> signingNodes = getSigningNodes(psbt);

        for(int i = 0; i < psbt.getTransaction().getInputs().size(); i++) {
            TransactionInput txInput = psbt.getTransaction().getInputs().get(i);
            PSBTInput psbtInput = psbt.getPsbtInputs().get(i);

            if(psbtInput.isFinalized()) {
                continue;
            }

            WalletNode signingNode = signingNodes.get(psbtInput);

            //Transaction parent on PSBT utxo might be null in a witness tx, so get utxo tx hash and utxo index from PSBT tx input
            TransactionOutput utxo = new TransactionOutput(null, psbtInput.getUtxo().getValue(), psbtInput.getUtxo().getScript()) {
                @Override
                public Sha256Hash getHash() {
                    return txInput.getOutpoint().getHash();
                }

                @Override
                public int getIndex() {
                    return (int)txInput.getOutpoint().getIndex();
                }
            };

            //TODO: Handle taproot scriptpath spending
            int signaturesAvailable = psbtInput.isTaproot() ? (psbtInput.getTapKeyPathSignature() != null ? 1 : 0) : psbtInput.getPartialSignatures().size();
            if(signaturesAvailable >= threshold && signingNode != null) {
                Transaction transaction = new Transaction();

                TransactionInput finalizedTxInput;
                if(getPolicyType().equals(PolicyType.SINGLE)) {
                    ECKey pubKey = signingNode.getPubKey();
                    TransactionSignature transactionSignature = psbtInput.isTaproot() ? psbtInput.getTapKeyPathSignature() : psbtInput.getPartialSignature(pubKey);
                    if(transactionSignature == null) {
                        throw new IllegalArgumentException("Pubkey of partial signature does not match wallet pubkey");
                    }

                    finalizedTxInput = signingNode.getWallet().getScriptType().addSpendingInput(transaction, utxo, pubKey, transactionSignature);
                } else if(getPolicyType().equals(PolicyType.MULTI)) {
                    List<ECKey> pubKeys = signingNode.getPubKeys();

                    Map<ECKey, TransactionSignature> pubKeySignatures = new TreeMap<>(new ECKey.LexicographicECKeyComparator());
                    for(ECKey pubKey : pubKeys) {
                        pubKeySignatures.put(pubKey, psbtInput.getPartialSignature(pubKey));
                    }

                    List<TransactionSignature> signatures = pubKeySignatures.values().stream().filter(Objects::nonNull).collect(Collectors.toList());
                    if(signatures.size() < threshold) {
                        throw new IllegalArgumentException("Pubkeys of partial signatures do not match wallet pubkeys");
                    }

                    finalizedTxInput = signingNode.getWallet().getScriptType().addMultisigSpendingInput(transaction, utxo, threshold, pubKeySignatures);
                } else {
                    throw new UnsupportedOperationException("Cannot finalise PSBT for policy type " + getPolicyType());
                }

                psbtInput.setFinalScriptSig(finalizedTxInput.getScriptSig());
                psbtInput.setFinalScriptWitness(finalizedTxInput.getWitness());
                psbtInput.clearNonFinalFields();
            }
        }

        psbt.getPsbtOutputs().forEach(PSBTOutput::clearNonFinalFields);
    }

    public BitcoinUnit getAutoUnit() {
        for(KeyPurpose keyPurpose : KeyPurpose.values()) {
            for(WalletNode addressNode : getNode(keyPurpose).getChildren()) {
                for(BlockTransactionHashIndex output : addressNode.getTransactionOutputs()) {
                    if(output.getValue() >= BitcoinUnit.getAutoThreshold()) {
                        return BitcoinUnit.BTC;
                    }
                }
            }
        }

        return BitcoinUnit.SATOSHIS;
    }

    public void clearNodes(Wallet previousWallet) {
        detachedLabels.putAll(previousWallet.getDetachedLabels(true));
        purposeNodes.clear();
        transactions.clear();
        storedBlockHeight = 0;
    }

    public void clearHistory() {
        detachedLabels.putAll(getDetachedLabels(false));
        for(WalletNode purposeNode : purposeNodes) {
            purposeNode.clearHistory();
        }

        transactions.clear();
        storedBlockHeight = 0;

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                childWallet.clearHistory();
            }
        }
    }

    private Map<String, String> getDetachedLabels(boolean includeAddresses) {
        Map<String, String> labels = new HashMap<>();
        for(BlockTransaction blockTransaction : transactions.values()) {
            if(blockTransaction.getLabel() != null && !blockTransaction.getLabel().isEmpty()) {
                labels.put(blockTransaction.getHashAsString(), blockTransaction.getLabel());
            }
        }

        for(WalletNode purposeNode : purposeNodes) {
            for(WalletNode addressNode : purposeNode.getChildren()) {
                if(includeAddresses && addressNode.getLabel() != null && !addressNode.getLabel().isEmpty()) {
                    labels.put(addressNode.getAddress().toString(), addressNode.getLabel());
                }

                for(BlockTransactionHashIndex output : addressNode.getTransactionOutputs()) {
                    if(output.getLabel() != null && !output.getLabel().isEmpty()) {
                        labels.put(output.getHash().toString() + "<" + output.getIndex(), output.getLabel());
                    }

                    if(output.getStatus() != null) {
                        labels.put(output.getHash().toString() + ":" + output.getIndex(), output.getStatus().toString());
                    }

                    if(output.isSpent() && output.getSpentBy().getLabel() != null && !output.getSpentBy().getLabel().isEmpty()) {
                        labels.put(output.getSpentBy().getHash() + ">" + output.getSpentBy().getIndex(), output.getSpentBy().getLabel());
                    }
                }
            }
        }

        return labels;
    }

    public boolean isValid() {
        try {
            checkWallet();
        } catch(InvalidWalletException e) {
            return false;
        }

        return true;
    }

    public void checkWallet() throws InvalidWalletException {
        if(policyType == null) {
            throw new InvalidWalletException("No policy type specified");
        }

        if(scriptType == null) {
            throw new InvalidWalletException("No script type specified");
        }

        if(defaultPolicy == null) {
            throw new InvalidWalletException("No default policy specified");
        }

        if(keystores.isEmpty()) {
            throw new InvalidWalletException("No keystores specified");
        }

        if(!ScriptType.getScriptTypesForPolicyType(policyType).contains(scriptType)) {
            throw new InvalidWalletException("Script type of " + scriptType + " is not valid for a policy type of " + policyType);
        }

        int numSigs;
        try {
            numSigs = defaultPolicy.getNumSignaturesRequired();
        } catch (Exception e) {
            throw new InvalidWalletException("Cannot determine number of required signatures to sign a transaction");
        }

        if(policyType.equals(PolicyType.SINGLE) && (numSigs != 1 || keystores.size() != 1)) {
            throw new InvalidWalletException(policyType + " wallet needs " + numSigs + " and has " + keystores.size() + " keystores");
        }

        if(policyType.equals(PolicyType.MULTI) && (numSigs < 1 || numSigs > keystores.size())) {
            throw new InvalidWalletException(policyType + " wallet needs " + numSigs + " and has " + keystores.size() + " keystores");
        }

        if(containsDuplicateKeystoreLabels()) {
            throw new InvalidWalletException("Wallet keystores have duplicate labels");
        }

        for(Keystore keystore : keystores) {
            try {
                keystore.checkKeystore();
            } catch(InvalidKeystoreException e) {
                throw new InvalidWalletException("Keystore " + keystore.getLabel() + " is invalid (" + e.getMessage() + ")", e);
            }

            if(derivationMatchesAnotherScriptType(keystore.getKeyDerivation().getDerivationPath())) {
                throw new InvalidWalletException("Keystore " + keystore.getLabel() + " derivation of " + keystore.getKeyDerivation().getDerivationPath() + " in " + scriptType.getName() + " wallet matches another default script type.");
            }

            if(derivationMatchesAnotherNetwork(keystore.getKeyDerivation().getDerivationPath())) {
                throw new InvalidWalletException("Keystore " + keystore.getLabel() + " derivation of " + keystore.getKeyDerivation().getDerivationPath() + " in " + scriptType.getName() + " wallet matches another network.");
            }
        }

        if(containsDuplicateExtendedKeys()) {
            throw new InvalidWalletException("Wallet keystores have duplicate extended public keys");
        }
    }

    public boolean derivationMatchesAnotherScriptType(String derivationPath) {
        if(Boolean.TRUE.toString().equals(System.getProperty(ALLOW_DERIVATIONS_MATCHING_OTHER_SCRIPT_TYPES_PROPERTY))) {
            return false;
        }

        if(scriptType != null && scriptType.getAccount(derivationPath) > -1) {
            return false;
        }

        return Arrays.stream(ScriptType.values()).anyMatch(scriptType -> !scriptType.equals(this.scriptType) && scriptType.getAccount(derivationPath, true) > -1);
    }

    public boolean derivationMatchesAnotherNetwork(String derivationPath) {
        if(Boolean.TRUE.toString().equals(System.getProperty(ALLOW_DERIVATIONS_MATCHING_OTHER_NETWORKS_PROPERTY))) {
            return false;
        }

        if(scriptType != null && scriptType.getAccount(derivationPath, true) > -1) {
            return ScriptType.derivationMatchesAnotherNetwork(derivationPath);
        }

        return false;
    }

    public boolean containsDuplicateKeystoreLabels() {
        if(keystores.size() <= 1) {
            return false;
        }

        return !keystores.stream().map(Keystore::getLabel).allMatch(new HashSet<>()::add);
    }

    public boolean containsDuplicateExtendedKeys() {
        if(keystores.size() <= 1) {
            return false;
        }

        return !keystores.stream().map(Keystore::getExtendedPublicKey).allMatch(new HashSet<>()::add);
    }

    public void makeLabelsUnique(Keystore newKeystore) {
        Set<String> labels = getKeystores().stream().map(Keystore::getBaseLabel).collect(Collectors.toSet());
        if(!labels.add(newKeystore.getBaseLabel())) {
            makeLabelsUnique(newKeystore, false);
        }
    }

    private int makeLabelsUnique(Keystore newKeystore, boolean duplicateFound) {
        int max = 0;
        for(Keystore keystore : getKeystores()) {
            String newKeystoreLabel = newKeystore.getLabel().equals(Keystore.DEFAULT_LABEL) ? Keystore.DEFAULT_LABEL.substring(0, Keystore.DEFAULT_LABEL.length() - 2) : newKeystore.getLabel();
            if(newKeystore != keystore && keystore.getLabel().startsWith(newKeystoreLabel)) {
                duplicateFound = true;
                String remainder = keystore.getLabel().substring(newKeystoreLabel.length());
                if(remainder.length() == 0) {
                    max = makeLabelsUnique(keystore, true);
                } else {
                    try {
                        int count = Integer.parseInt(remainder.trim());
                        max = Math.max(max, count);
                    } catch (NumberFormatException e) {
                        //ignore, no terminating number
                    }
                }
            }
        }

        if(duplicateFound) {
            max++;
            if(newKeystore.getLabel().equals(Keystore.DEFAULT_LABEL)) {
                newKeystore.setLabel(Keystore.DEFAULT_LABEL.substring(0, Keystore.DEFAULT_LABEL.length() - 2) + " " + max);
            } else if(newKeystore.getLabel().length() + Integer.toString(max).length() + 1 > Keystore.MAX_LABEL_LENGTH) {
                newKeystore.setLabel(newKeystore.getLabel().substring(0, Keystore.MAX_LABEL_LENGTH - (Integer.toString(max).length() + 1)) + " " + max);
            } else {
                newKeystore.setLabel(newKeystore.getLabel() + " " + max);
            }
        }

        return max;
    }

    public Wallet copy() {
        return copy(true);
    }

    public Wallet copy(boolean includeHistory) {
        Wallet copy = new Wallet(name);
        copy.setId(getId());
        copy.setLabel(label);
        copy.setMasterWallet(masterWallet);
        for(Wallet childWallet : childWallets) {
            Wallet copyChildWallet = childWallet.copy(includeHistory);
            copyChildWallet.setMasterWallet(copy);
            copy.childWallets.add(copyChildWallet);
        }
        copy.setPolicyType(policyType);
        copy.setScriptType(scriptType);
        copy.setDefaultPolicy(defaultPolicy.copy());
        for(Keystore keystore : keystores) {
            copy.getKeystores().add(keystore.copy());
        }
        if(includeHistory) {
            for(WalletNode node : purposeNodes) {
                copy.purposeNodes.add(node.copy(copy));
            }
            for(Sha256Hash hash : transactions.keySet()) {
                copy.transactions.put(hash, transactions.get(hash));
            }
            for(String entry : detachedLabels.keySet()) {
                copy.detachedLabels.put(entry, detachedLabels.get(entry));
            }
            for(Sha256Hash hash : utxoMixes.keySet()) {
                copy.utxoMixes.put(hash, utxoMixes.get(hash));
            }
        }
        copy.setWalletConfig(walletConfig == null ? null : walletConfig.copy());
        copy.setMixConfig(mixConfig == null ? null : mixConfig.copy());
        copy.setStoredBlockHeight(getStoredBlockHeight());
        copy.gapLimit = gapLimit;
        copy.watchLast = watchLast;
        copy.birthDate = birthDate;

        return copy;
    }

    public boolean containsMasterPrivateKeys() {
        for(Keystore keystore : keystores) {
            if(keystore.hasMasterPrivateKey()) {
                return true;
            }
        }

        return false;
    }

    public boolean containsSource(KeystoreSource keystoreSource) {
        for(Keystore keystore : keystores) {
            if(keystoreSource.equals(keystore.getSource())) {
                return true;
            }
        }

        return false;
    }

    public boolean isEncrypted() {
        for(Keystore keystore : keystores) {
            if(keystore.isEncrypted()) {
                return true;
            }
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested() && childWallet.isEncrypted()) {
                return true;
            }
        }

        return false;
    }

    public void encrypt(Key key) {
        for(Keystore keystore : keystores) {
            keystore.encrypt(key);
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                childWallet.encrypt(key);
            }
        }
    }

    public void decrypt(CharSequence password) {
        for(Keystore keystore : keystores) {
            keystore.decrypt(password);
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                childWallet.decrypt(password);
            }
        }
    }

    public void decrypt(Key key) {
        for(Keystore keystore : keystores) {
            keystore.decrypt(key);
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                childWallet.decrypt(key);
            }
        }
    }

    public void clearPrivate() {
        for(Keystore keystore : keystores) {
            keystore.clearPrivate();
        }

        for(Wallet childWallet : getChildWallets()) {
            if(childWallet.isNested()) {
                childWallet.clearPrivate();
            }
        }
    }

    @Override
    public int compareTo(Wallet other) {
        if(isMasterWallet() && !other.isMasterWallet()) {
            return -1;
        }

        if(!isMasterWallet() && other.isMasterWallet()) {
            return 1;
        }

        if(getStandardAccountType() != null && other.getStandardAccountType() != null) {
            int standardAccountDiff = getStandardAccountType().ordinal() - other.getStandardAccountType().ordinal();
            if(standardAccountDiff != 0) {
                return standardAccountDiff;
            }
        }

        int accountIndexDiff = getAccountIndex() - other.getAccountIndex();
        if(accountIndexDiff != 0) {
            return accountIndexDiff;
        }

        if(name != null && other.name != null) {
            return name.compareTo(other.name);
        }

        return 0;
    }

    @Override
    public String toString() {
        return getFullName();
    }
}
