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

import java.util.*;
import java.util.stream.Collectors;

public class Wallet {
    private static final int DEFAULT_LOOKAHEAD = 20;

    private String name;
    private PolicyType policyType;
    private ScriptType scriptType;
    private Policy defaultPolicy;
    private List<Keystore> keystores = new ArrayList<>();
    private final List<Node> accountNodes = new ArrayList<>();

    private transient int lookAhead = DEFAULT_LOOKAHEAD;

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

    public Node getNode(KeyPurpose keyPurpose) {
        Node purposeNode;
        Optional<Node> optionalPurposeNode = accountNodes.stream().filter(node -> node.getKeyPurpose().equals(keyPurpose)).findFirst();
        if(optionalPurposeNode.isEmpty()) {
            purposeNode = new Node(keyPurpose);
            accountNodes.add(purposeNode);
        } else {
            purposeNode = optionalPurposeNode.get();
        }

        purposeNode.fillToLookAhead(getLookAhead());
        return purposeNode;
    }

    public int getLookAhead() {
        //TODO: Calculate using seen transactions
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
            lookAhead = index;
            node.fillToLookAhead(lookAhead);
        }

        return node.getChildren().get(index);
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

    public class Node {
        private final String derivationPath;
        private String label;
        private Long amount;
        private final List<Node> children = new ArrayList<>();

        private final transient KeyPurpose keyPurpose;
        private final transient int index;
        private final transient List<ChildNumber> derivation;

        public Node(String derivationPath) {
            this.derivationPath = derivationPath;
            this.derivation = KeyDerivation.parsePath(derivationPath);
            this.keyPurpose = KeyPurpose.fromChildNumber(derivation.get(0));
            this.index = derivation.get(derivation.size() - 1).num();
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

        public int getIndex() {
            return index;
        }

        public KeyPurpose getKeyPurpose() {
            return keyPurpose;
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

        public List<Node> getChildren() {
            return children;
        }

        public Address getAddress() {
            return Wallet.this.getAddress(keyPurpose, index);
        }

        public Script getOutputScript() {
            return Wallet.this.getOutputScript(keyPurpose, index);
        }

        public void fillToLookAhead(int lookAhead) {
            for(int i = 0; i < lookAhead; i++) {
                Node node = new Node(getKeyPurpose(), i);
                if(!getChildren().contains(node)) {
                    getChildren().add(node);
                }
            }
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
    }
}
