package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Script;

import java.util.*;
import java.util.stream.Collectors;

public class WalletNode extends Persistable implements Comparable<WalletNode> {
    private final String derivationPath;
    private String label;
    private Address address;
    private TreeSet<WalletNode> children = new TreeSet<>();
    private TreeSet<BlockTransactionHashIndex> transactionOutputs = new TreeSet<>();

    private transient Wallet wallet;
    private transient KeyPurpose keyPurpose;
    private transient int index = -1;
    private transient List<ChildNumber> derivation;

    //Cache pubkeys for BIP47 wallets to avoid time-consuming ECDH calculations
    private transient ECKey cachedPubKey;

    //Note use of this constructor must be followed by setting the wallet field
    public WalletNode(String derivationPath) {
        this.derivationPath = derivationPath;
        parseDerivation();
    }

    public WalletNode(Wallet wallet, String derivationPath) {
        this.wallet = wallet;
        this.derivationPath = derivationPath;
        parseDerivation();
    }

    public WalletNode(Wallet wallet, KeyPurpose keyPurpose) {
        this.wallet = wallet;
        this.derivation = List.of(keyPurpose.getPathIndex());
        this.derivationPath = KeyDerivation.writePath(derivation);
        this.keyPurpose = keyPurpose;
        this.index = keyPurpose.getPathIndex().num();
    }

    public WalletNode(Wallet wallet, KeyPurpose keyPurpose, int index) {
        this.wallet = wallet;
        this.derivation = List.of(keyPurpose.getPathIndex(), new ChildNumber(index));
        this.derivationPath = KeyDerivation.writePath(derivation);
        this.keyPurpose = keyPurpose;
        this.index = index;
    }

    public Wallet getWallet() {
        return wallet;
    }

    public void setWallet(Wallet wallet) {
        this.wallet = wallet;
        for(WalletNode childNode : getChildren()) {
            childNode.setWallet(wallet);
        }
    }

    public String getDerivationPath() {
        return derivationPath;
    }

    public void parseDerivation() {
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

    public Long getValue() {
        if(transactionOutputs == null) {
            return null;
        }

        return getUnspentTransactionOutputs().stream().mapToLong(BlockTransactionHashIndex::getValue).sum();
    }

    public Set<WalletNode> getChildren() {
        return children;
    }

    public void setChildren(TreeSet<WalletNode> children) {
        this.children = children;
    }

    public boolean isUsed() {
        return !transactionOutputs.isEmpty();
    }

    public Set<BlockTransactionHashIndex> getTransactionOutputs() {
        return transactionOutputs;
    }

    public void setTransactionOutputs(TreeSet<BlockTransactionHashIndex> transactionOutputs) {
        this.transactionOutputs = transactionOutputs;
    }

    public synchronized void updateTransactionOutputs(Wallet wallet, Set<BlockTransactionHashIndex> updatedOutputs) {
        for(BlockTransactionHashIndex txo : updatedOutputs) {
            if(!transactionOutputs.isEmpty()) {
                Optional<String> optionalLabel = transactionOutputs.stream().filter(oldTxo -> oldTxo.getHash().equals(txo.getHash()) && oldTxo.getIndex() == txo.getIndex()).map(BlockTransactionHash::getLabel).filter(Objects::nonNull).findFirst();
                optionalLabel.ifPresent(txo::setLabel);
                Optional<Status> optionalStatus = transactionOutputs.stream().filter(oldTxo -> oldTxo.getHash().equals(txo.getHash()) && oldTxo.getIndex() == txo.getIndex()).map(BlockTransactionHashIndex::getStatus).filter(Objects::nonNull).findFirst();
                optionalStatus.ifPresent(txo::setStatus);
            }

            if(!wallet.getDetachedLabels().isEmpty()) {
                String label = wallet.getDetachedLabels().remove(txo.getHash().toString() + "<" + txo.getIndex());
                if(label != null && (txo.getLabel() == null || txo.getLabel().isEmpty())) {
                    txo.setLabel(label);
                }

                String status = wallet.getDetachedLabels().remove(txo.getHash().toString() + ":" + txo.getIndex());
                if(status != null && txo.getStatus() == null) {
                    txo.setStatus(Status.valueOf(status));
                }

                if(txo.isSpent()) {
                    String spentByLabel = wallet.getDetachedLabels().remove(txo.getSpentBy().getHash() + ">" + txo.getSpentBy().getIndex());
                    if(spentByLabel != null && (txo.getSpentBy().getLabel() == null || txo.getSpentBy().getLabel().isEmpty())) {
                        txo.getSpentBy().setLabel(spentByLabel);
                    }
                }
            }

            if(txo.isSpent() && txo.getStatus() == Status.FROZEN) {
                txo.setStatus(null);
            }
        }

        transactionOutputs.clear();
        transactionOutputs.addAll(updatedOutputs);
    }

    public Set<BlockTransactionHashIndex> getUnspentTransactionOutputs() {
        return getTransactionOutputs(List.of(new SpentTxoFilter()));
    }

    public Set<BlockTransactionHashIndex> getTransactionOutputs(Collection<TxoFilter> txoFilters) {
        if(transactionOutputs.isEmpty()) {
            return Collections.emptySet();
        }

        Set<BlockTransactionHashIndex> unspentTXOs = new TreeSet<>(transactionOutputs);
        unspentTXOs.removeIf(txo -> !txoFilters.stream().allMatch(txoFilter -> txoFilter.isEligible(txo)));
        return unspentTXOs;
    }

    public long getUnspentValue() {
        long value = 0L;
        for(BlockTransactionHashIndex utxo : getUnspentTransactionOutputs()) {
            value += utxo.getValue();
        }

        return value;
    }

    public Set<WalletNode> fillToIndex(Wallet wallet, int index) {
        Set<WalletNode> newNodes = fillToIndex(index);
        if(wallet.isValid()) {
            if(!wallet.getDetachedLabels().isEmpty()) {
                for(WalletNode newNode : newNodes) {
                    String label = wallet.getDetachedLabels().remove(newNode.getAddress().toString());
                    if(label != null && (newNode.getLabel() == null || newNode.getLabel().isEmpty())) {
                        newNode.setLabel(label);
                    }
                }
            }

            if(wallet.isBip47() && keyPurpose == KeyPurpose.RECEIVE && wallet.getLabel() != null && !newNodes.isEmpty()) {
                String suffix = " " + wallet.getScriptType().getName();
                for(WalletNode newNode : newNodes) {
                    if((newNode.getLabel() == null || newNode.getLabel().isEmpty()) && wallet.getLabel().endsWith(suffix)) {
                        newNode.setLabel("From " + wallet.getLabel().substring(0, wallet.getLabel().length() - suffix.length()));
                    }
                }
            }
        }

        return newNodes;
    }

    public synchronized Set<WalletNode> fillToIndex(int index) {
        //Optimization to check if child nodes already monotonically increment to the desired index
        int indexCheck = 0;
        for(WalletNode childNode : getChildren()) {
            if(childNode.index == indexCheck) {
                indexCheck++;
            } else {
                break;
            }

            if(childNode.index == index) {
                return Collections.emptySet();
            }
        }

        Set<WalletNode> newNodes = new TreeSet<>();
        for(int i = 0; i <= index; i++) {
            WalletNode node = new WalletNode(wallet, getKeyPurpose(), i);
            if(children.add(node)) {
                newNodes.add(node);
            }
        }

        return newNodes;
    }

    /**
     * @return The highest used index, or null if no addresses are used
     */
    public Integer getHighestUsedIndex() {
        WalletNode highestNode = null;
        for(WalletNode childNode : getChildren()) {
            if(!childNode.getTransactionOutputs().isEmpty()) {
                highestNode = childNode;
            }
        }

        return highestNode == null ? null : highestNode.index;
    }

    public ECKey getPubKey() {
        if(cachedPubKey != null) {
            return cachedPubKey;
        }

        if(wallet.isBip47()) {
            cachedPubKey = wallet.getPubKey(this);
            return cachedPubKey;
        }

        return wallet.getPubKey(this);
    }

    public List<ECKey> getPubKeys() {
        return wallet.getPubKeys(this);
    }

    public Address getAddress() {
        if(address != null) {
            return address;
        }

        Wallet masterWallet = wallet.isMasterWallet() ? wallet : wallet.getMasterWallet();
        if(masterWallet.getKeystores().stream().noneMatch(Keystore::needsPassphrase)) {
            address = wallet.getAddress(this);
            return address;
        }

        return wallet.getAddress(this);
    }

    public byte[] getAddressData() {
        return address == null ? null : address.getData();
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public Script getOutputScript() {
        return getAddress().getOutputScript();
    }

    public String getOutputDescriptor() {
        return wallet.getOutputDescriptor(this);
    }

    @Override
    public String toString() {
        return derivationPath.replace("m", "..");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WalletNode node = (WalletNode) o;
        return Objects.equals(wallet, node.wallet) && derivationPath.equals(node.derivationPath);
    }

    @Override
    public int hashCode() {
        return Objects.hash(wallet, derivationPath);
    }

    @Override
    public int compareTo(WalletNode node) {
        if(getDerivation().size() != node.getDerivation().size()) {
            return getDerivation().size() - node.getDerivation().size();
        }

        for(int i = 0; i < getDerivation().size(); i++) {
            ChildNumber thisChild = getDerivation().get(i);
            ChildNumber nodeChild = node.getDerivation().get(i);
            if(thisChild.num() != nodeChild.num()) {
                return thisChild.num() - nodeChild.num();
            }
        }

        return 0;
    }

    public synchronized void clearHistory() {
        transactionOutputs.clear();
        for(WalletNode childNode : getChildren()) {
            childNode.clearHistory();
        }
    }

    public WalletNode copy(Wallet walletCopy) {
        WalletNode copy = new WalletNode(walletCopy, derivationPath);
        copy.setId(getId());
        copy.setLabel(label);
        copy.setAddress(address);

        for(WalletNode child : getChildren()) {
            copy.children.add(child.copy(walletCopy));
        }

        for(BlockTransactionHashIndex txo : getTransactionOutputs()) {
            copy.transactionOutputs.add(txo.copy());
        }

        return copy;
    }

    public static String nodeRangesToString(Set<WalletNode> nodes) {
        return nodeRangesToString(nodes.stream().map(WalletNode::getDerivationPath).collect(Collectors.toList()));
    }

    public static String nodeRangesToString(Collection<String> nodeDerivations) {
        List<String> sortedDerivations = new ArrayList<>(nodeDerivations);

        if(nodeDerivations.isEmpty()) {
            return "[]";
        }

        List<List<String>> contiguous = splitToContiguous(sortedDerivations);

        String abbrev = "[";
        for(Iterator<List<String>> iter = contiguous.iterator(); iter.hasNext(); ) {
            List<String> range = iter.next();
            abbrev += range.get(0);
            if(range.size() > 1) {
                abbrev += "-" + range.get(range.size() - 1);
            }
            if(iter.hasNext()) {
                abbrev += ", ";
            }
        }
        abbrev += "]";

        return abbrev;
    }

    private static List<List<String>> splitToContiguous(List<String> input) {
        List<List<String>> result = new ArrayList<>();
        int prev = 0;

        int keyPurpose = getKeyPurpose(input.get(0));
        int index = getIndex(input.get(0));

        for (int cur = 0; cur < input.size(); cur++) {
            if(getKeyPurpose(input.get(cur)) != keyPurpose || getIndex(input.get(cur)) != index) {
                result.add(input.subList(prev, cur));
                prev = cur;
            }
            index = getIndex(input.get(cur)) + 1;
            keyPurpose = getKeyPurpose(input.get(cur));
        }
        result.add(input.subList(prev, input.size()));

        return result;
    }

    private static int getKeyPurpose(String path) {
        List<ChildNumber> childNumbers = KeyDerivation.parsePath(path);
        if(childNumbers.isEmpty()) {
            return -1;
        }
        return childNumbers.get(0).num();
    }

    private static int getIndex(String path) {
        List<ChildNumber> childNumbers = KeyDerivation.parsePath(path);
        if(childNumbers.isEmpty()) {
            return -1;
        }
        return childNumbers.get(childNumbers.size() - 1).num();
    }
}
