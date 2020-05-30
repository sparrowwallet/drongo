package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.crypto.ChildNumber;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

public class WalletNode implements Comparable<WalletNode> {
    private final String derivationPath;
    private String label;
    private Long amount;
    private Set<WalletNode> children = new TreeSet<>();
    private Set<TransactionReference> history = new TreeSet<>();

    private transient KeyPurpose keyPurpose;
    private transient int index = -1;
    private transient List<ChildNumber> derivation;

    public WalletNode(String derivationPath) {
        this.derivationPath = derivationPath;
        parseDerivation();
    }

    public WalletNode(KeyPurpose keyPurpose) {
        this.derivation = List.of(keyPurpose.getPathIndex());
        this.derivationPath = KeyDerivation.writePath(derivation);
        this.keyPurpose = keyPurpose;
        this.index = keyPurpose.getPathIndex().num();
    }

    public WalletNode(KeyPurpose keyPurpose, int index) {
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

    public Set<WalletNode> getChildren() {
        return children;
    }

    public void setChildren(Set<WalletNode> children) {
        this.children = children;
    }

    public Set<TransactionReference> getHistory() {
        return history;
    }

    public void setHistory(Set<TransactionReference> history) {
        this.history = history;
    }

    public void fillToIndex(int index) {
        for(int i = 0; i <= index; i++) {
            WalletNode node = new WalletNode(getKeyPurpose(), i);
            getChildren().add(node);
        }
    }

    public Integer getHighestIndex() {
        WalletNode highestNode = null;
        for(WalletNode childNode : getChildren()) {
            highestNode = childNode;
        }

        return highestNode == null ? null : highestNode.index;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WalletNode node = (WalletNode) o;
        return derivationPath.equals(node.derivationPath);
    }

    @Override
    public int hashCode() {
        return Objects.hash(derivationPath);
    }

    @Override
    public int compareTo(WalletNode node) {
        return getIndex() - node.getIndex();
    }

    public WalletNode copy() {
        WalletNode copy = new WalletNode(derivationPath);
        copy.setLabel(label);
        copy.setAmount(amount);
        for(WalletNode child : getChildren()) {
            copy.getChildren().add(child.copy());
        }
        for(TransactionReference reference : getHistory()) {
            copy.getHistory().add(reference.copy());
        }

        return copy;
    }
}
