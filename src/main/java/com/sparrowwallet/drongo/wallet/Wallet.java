package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Transaction;

import java.util.*;
import java.util.stream.Collectors;

public class Wallet {
    private static final int DEFAULT_LOOKAHEAD = 20;

    private String name;
    private PolicyType policyType;
    private ScriptType scriptType;
    private Policy defaultPolicy;
    private List<Keystore> keystores = new ArrayList<>();
    private final Set<Node> purposeNodes = new TreeSet<>();
    private final Map<String, Transaction> transactions = new HashMap<>();

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

    private Set<Node> getPurposeNodes() {
        return purposeNodes;
    }

    public Map<String, Transaction> getTransactions() {
        return transactions;
    }

    public Node getNode(KeyPurpose keyPurpose) {
        Node purposeNode;
        Optional<Node> optionalPurposeNode = purposeNodes.stream().filter(node -> node.getKeyPurpose().equals(keyPurpose)).findFirst();
        if(optionalPurposeNode.isEmpty()) {
            purposeNode = new Node(keyPurpose);
            purposeNodes.add(purposeNode);
        } else {
            purposeNode = optionalPurposeNode.get();
        }

        purposeNode.fillToIndex(getLookAhead(purposeNode) - 1);
        return purposeNode;
    }

    public int getLookAhead(Node node) {
        //TODO: Calculate using seen transactions
        int lookAhead = DEFAULT_LOOKAHEAD;
        Integer maxIndex = node.getHighestIndex();
        if(maxIndex != null) {
            lookAhead = Math.max(maxIndex + lookAhead/2, lookAhead);
        }

        return lookAhead;
    }

    public Node getFreshNode(KeyPurpose keyPurpose) {
        //TODO: Calculate using seen transactions
        return getFreshNode(keyPurpose, null);
    }

    public Node getFreshNode(KeyPurpose keyPurpose, Node current) {
        //TODO: Calculate using seen transactions
        int index = 0;
        if(current != null) {
            index = current.getIndex() + 1;
        }

        Node node = getNode(keyPurpose);
        if(index >= node.getChildren().size()) {
            node.fillToIndex(index);
        }

        for(Node childNode : node.getChildren()) {
            if(childNode.getIndex() == index) {
                return childNode;
            }
        }

        throw new IllegalStateException("Could not fill nodes to index " + index);
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
        for(Wallet.Node node : purposeNodes) {
            Node nodeCopy = copy.copyNode(node);
            copy.getPurposeNodes().add(nodeCopy);
        }
        return copy;
    }

    private Node copyNode(Node node) {
        Node copy = new Node(node.derivationPath);
        copy.setLabel(node.label);
        copy.setAmount(node.amount);
        for(Node child : node.getChildren()) {
            copy.getChildren().add(copyNode(child));
        }
        for(TransactionReference reference : node.getHistory()) {
            copy.getHistory().add(reference.copy());
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

    public class Node implements Comparable<Node> {
        private final String derivationPath;
        private String label;
        private Long amount;
        private Set<Node> children = new TreeSet<>();
        private Set<TransactionReference> history = new TreeSet<>();

        private transient KeyPurpose keyPurpose;
        private transient int index = -1;
        private transient List<ChildNumber> derivation;

        public Node(String derivationPath) {
            this.derivationPath = derivationPath;
            parseDerivation();
        }

        public Node(KeyPurpose keyPurpose) {
            this.derivation = List.of(keyPurpose.getPathIndex());
            this.derivationPath = KeyDerivation.writePath(derivation);
            this.keyPurpose = keyPurpose;
            this.index = keyPurpose.getPathIndex().num();
        }

        public Node(KeyPurpose keyPurpose, int index) {
            this.derivation = List.of(keyPurpose.getPathIndex(), new ChildNumber(index));
            this.derivationPath = KeyDerivation.writePath(derivation);
            this.keyPurpose = keyPurpose;
            this.index = index;
        }

        public String getDerivationPath() {
            return derivationPath;
        }

        private void parseDerivation() {
            this.derivation = KeyDerivation.parsePath(derivationPath);
            this.keyPurpose = KeyPurpose.fromChildNumber(derivation.get(0));
            this.index = derivation.get(derivation.size() - 1).num();
        }

        public int getIndex() {
            if(index < 0) {
                parseDerivation();
            }

            return index;
        }

        public KeyPurpose getKeyPurpose() {
            if(keyPurpose == null) {
                parseDerivation();
            }

            return keyPurpose;
        }

        public List<ChildNumber> getDerivation() {
            if(derivation == null) {
                parseDerivation();
            }

            return derivation;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public Long getAmount() {
            return amount;
        }

        public void setAmount(Long amount) {
            this.amount = amount;
        }

        public Set<Node> getChildren() {
            return children;
        }

        public void setChildren(Set<Node> children) {
            this.children = children;
        }

        public Set<TransactionReference> getHistory() {
            return history;
        }

        public void setHistory(Set<TransactionReference> history) {
            this.history = history;
        }

        public Address getAddress() {
            return Wallet.this.getAddress(keyPurpose, index);
        }

        public Script getOutputScript() {
            return Wallet.this.getOutputScript(keyPurpose, index);
        }

        public String getOutputDescriptor() {
            return Wallet.this.getOutputDescriptor(keyPurpose, index);
        }

        public void fillToIndex(int index) {
            for(int i = 0; i <= index; i++) {
                Node node = new Node(getKeyPurpose(), i);
                getChildren().add(node);
            }
        }

        public Integer getHighestIndex() {
            Node highestNode = null;
            for(Node childNode : getChildren()) {
                highestNode = childNode;
            }

            return highestNode == null ? null : highestNode.index;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Node node = (Node) o;
            return derivationPath.equals(node.derivationPath);
        }

        @Override
        public int hashCode() {
            return Objects.hash(derivationPath);
        }

        @Override
        public int compareTo(Node node) {
            return getIndex() - node.getIndex();
        }
    }
}
