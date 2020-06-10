package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;

import java.util.*;
import java.util.stream.Collectors;

public class Wallet {
    private static final int DEFAULT_LOOKAHEAD = 20;

    private String name;
    private PolicyType policyType;
    private ScriptType scriptType;
    private Policy defaultPolicy;
    private List<Keystore> keystores = new ArrayList<>();
    private final Set<WalletNode> purposeNodes = new TreeSet<>();
    private final Map<Sha256Hash, BlockTransaction> transactions = new HashMap<>();

    public Wallet() {
    }

    public Wallet(String name) {
        this.name = name;
    }

    public Wallet(String name, PolicyType policyType, ScriptType scriptType) {
        this.name = name;
        this.policyType = policyType;
        this.scriptType = scriptType;
        this.keystores = Collections.singletonList(new Keystore());
        this.defaultPolicy = Policy.getPolicy(policyType, scriptType, keystores, null);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
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

    public void setKeystores(List<Keystore> keystores) {
        this.keystores = keystores;
    }

    private Set<WalletNode> getPurposeNodes() {
        return purposeNodes;
    }

    public Map<Sha256Hash, BlockTransaction> getTransactions() {
        return transactions;
    }

    public WalletNode getNode(KeyPurpose keyPurpose) {
        WalletNode purposeNode;
        Optional<WalletNode> optionalPurposeNode = purposeNodes.stream().filter(node -> node.getKeyPurpose().equals(keyPurpose)).findFirst();
        if(optionalPurposeNode.isEmpty()) {
            purposeNode = new WalletNode(keyPurpose);
            purposeNodes.add(purposeNode);
        } else {
            purposeNode = optionalPurposeNode.get();
        }

        purposeNode.fillToIndex(getLookAhead(purposeNode) - 1);
        return purposeNode;
    }

    public int getLookAhead(WalletNode node) {
        int lookAhead = DEFAULT_LOOKAHEAD;
        Integer highestUsed = node.getHighestUsedIndex();
        if(highestUsed != null) {
            lookAhead = Math.max(highestUsed + lookAhead/2, lookAhead);
        }

        return lookAhead;
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
            node.fillToIndex(index);
        }

        for(WalletNode childNode : node.getChildren()) {
            if(childNode.getIndex() == index) {
                return childNode;
            }
        }

        throw new IllegalStateException("Could not fill nodes to index " + index);
    }

    public Address getAddress(WalletNode node) {
        return getAddress(node.getKeyPurpose(), node.getIndex());
    }

    public Address getAddress(KeyPurpose keyPurpose, int index) {
        if(policyType == PolicyType.SINGLE) {
            Keystore keystore = getKeystores().get(0);
            DeterministicKey key = keystore.getKey(keyPurpose, index);
            return scriptType.getAddress(key);
        } else if(policyType == PolicyType.MULTI) {
            List<ECKey> pubKeys = getKeystores().stream().map(keystore -> keystore.getKey(keyPurpose, index)).collect(Collectors.toList());
            Script script = ScriptType.MULTISIG.getOutputScript(defaultPolicy.getNumSignaturesRequired(), pubKeys);
            return scriptType.getAddress(script);
        } else {
            throw new UnsupportedOperationException("Cannot determine addresses for custom policies");
        }
    }

    public Script getOutputScript(WalletNode node) {
        return getOutputScript(node.getKeyPurpose(), node.getIndex());
    }

    public Script getOutputScript(KeyPurpose keyPurpose, int index) {
        if(policyType == PolicyType.SINGLE) {
            Keystore keystore = getKeystores().get(0);
            DeterministicKey key = keystore.getKey(keyPurpose, index);
            return scriptType.getOutputScript(key);
        } else if(policyType == PolicyType.MULTI) {
            List<ECKey> pubKeys = getKeystores().stream().map(keystore -> keystore.getKey(keyPurpose, index)).collect(Collectors.toList());
            Script script = ScriptType.MULTISIG.getOutputScript(defaultPolicy.getNumSignaturesRequired(), pubKeys);
            return scriptType.getOutputScript(script);
        } else {
            throw new UnsupportedOperationException("Cannot determine output script for custom policies");
        }
    }

    public String getOutputDescriptor(WalletNode node) {
        return getOutputDescriptor(node.getKeyPurpose(), node.getIndex());
    }

    public String getOutputDescriptor(KeyPurpose keyPurpose, int index) {
        if(policyType == PolicyType.SINGLE) {
            Keystore keystore = getKeystores().get(0);
            DeterministicKey key = keystore.getKey(keyPurpose, index);
            return scriptType.getOutputDescriptor(key);
        } else if(policyType == PolicyType.MULTI) {
            List<ECKey> pubKeys = getKeystores().stream().map(keystore -> keystore.getKey(keyPurpose, index)).collect(Collectors.toList());
            Script script = ScriptType.MULTISIG.getOutputScript(defaultPolicy.getNumSignaturesRequired(), pubKeys);
            return scriptType.getOutputDescriptor(script);
        } else {
            throw new UnsupportedOperationException("Cannot determine output descriptor for custom policies");
        }
    }

    public void clearHistory() {
        for(WalletNode purposeNode : purposeNodes) {
            purposeNode.clearHistory();
        }

        transactions.clear();
    }

    public boolean isValid() {
        if(policyType == null || scriptType == null || defaultPolicy == null || keystores.isEmpty()) {
            return false;
        }

        if(!ScriptType.getScriptTypesForPolicyType(policyType).contains(scriptType)) {
            return false;
        }

        int numSigs;
        try {
            numSigs = defaultPolicy.getNumSignaturesRequired();
        } catch (Exception e) {
            return false;
        }

        if(policyType.equals(PolicyType.SINGLE) && (numSigs != 1 || keystores.size() != 1)) {
            return false;
        }

        if(policyType.equals(PolicyType.MULTI) && (numSigs <= 1 || numSigs > keystores.size())) {
            return false;
        }

        if(containsDuplicateKeystoreLabels()) {
            return false;
        }

        for(Keystore keystore : keystores) {
            if(!keystore.isValid()) {
                return false;
            }
            if(derivationMatchesAnotherScriptType(keystore.getKeyDerivation().getDerivationPath())) {
                return false;
            }
        }

        return true;
    }

    public boolean derivationMatchesAnotherScriptType(String derivationPath) {
        if(scriptType != null && scriptType.getAccount(derivationPath) > -1) {
            return false;
        }

        return Arrays.stream(ScriptType.values()).anyMatch(scriptType -> !scriptType.equals(this.scriptType) && scriptType.getAccount(derivationPath) > -1);
    }

    public boolean containsDuplicateKeystoreLabels() {
        if(keystores.size() <= 1) {
            return false;
        }

        return !keystores.stream().map(Keystore::getLabel).allMatch(new HashSet<>()::add);
    }

    public void makeLabelsUnique(Keystore newKeystore) {
        makeLabelsUnique(newKeystore, false);
    }

    private int makeLabelsUnique(Keystore newKeystore, boolean duplicateFound) {
        int max = 0;
        for(Keystore keystore : getKeystores()) {
            if(newKeystore != keystore && keystore.getLabel().startsWith(newKeystore.getLabel())) {
                duplicateFound = true;
                String remainder = keystore.getLabel().substring(newKeystore.getLabel().length());
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
            newKeystore.setLabel(newKeystore.getLabel() + " " + max);
        }

        return max;
    }

    public Wallet copy() {
        Wallet copy = new Wallet(name);
        copy.setPolicyType(policyType);
        copy.setScriptType(scriptType);
        copy.setDefaultPolicy(defaultPolicy.copy());
        for(Keystore keystore : keystores) {
            copy.getKeystores().add(keystore.copy());
        }
        for(WalletNode node : purposeNodes) {
            copy.getPurposeNodes().add(node.copy());
        }
        for(Sha256Hash hash : transactions.keySet()) {
            copy.getTransactions().put(hash, transactions.get(hash));
        }

        return copy;
    }

    public boolean containsSeeds() {
        for(Keystore keystore : keystores) {
            if(keystore.hasSeed()) {
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

        return false;
    }

    public void encrypt(Key key) {
        for(Keystore keystore : keystores) {
            keystore.encrypt(key);
        }
    }

    public void decrypt(CharSequence password) {
        for(Keystore keystore : keystores) {
            keystore.decrypt(password);
        }
    }

    public void decrypt(Key key) {
        for(Keystore keystore : keystores) {
            keystore.decrypt(key);
        }
    }

    public void clearPrivate() {
        for(Keystore keystore : keystores) {
            keystore.clearPrivate();
        }
    }

}
