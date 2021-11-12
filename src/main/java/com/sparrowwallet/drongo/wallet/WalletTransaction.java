package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.psbt.PSBT;

import java.util.*;

/**
 * WalletTransaction contains a draft transaction along with associated metadata. The draft transaction has empty signatures but is otherwise complete.
 * This object represents an intermediate step before the transaction is signed or a PSBT is created from it.
 */
public class WalletTransaction {
    private final Wallet wallet;
    private final Transaction transaction;
    private final List<UtxoSelector> utxoSelectors;
    private final List<Map<BlockTransactionHashIndex, WalletNode>> selectedUtxoSets;
    private final List<Payment> payments;
    private final Map<WalletNode, Long> changeMap;
    private final long fee;
    private final Map<Sha256Hash, BlockTransaction> inputTransactions;

    public WalletTransaction(Wallet wallet, Transaction transaction, List<UtxoSelector> utxoSelectors, List<Map<BlockTransactionHashIndex, WalletNode>> selectedUtxoSets, List<Payment> payments, long fee) {
        this(wallet, transaction, utxoSelectors, selectedUtxoSets, payments, Collections.emptyMap(), fee);
    }

    public WalletTransaction(Wallet wallet, Transaction transaction, List<UtxoSelector> utxoSelectors, List<Map<BlockTransactionHashIndex, WalletNode>> selectedUtxoSets, List<Payment> payments, Map<WalletNode, Long> changeMap, long fee) {
        this(wallet, transaction, utxoSelectors, selectedUtxoSets, payments, changeMap, fee, Collections.emptyMap());
    }

    public WalletTransaction(Wallet wallet, Transaction transaction, List<UtxoSelector> utxoSelectors, List<Map<BlockTransactionHashIndex, WalletNode>> selectedUtxoSets, List<Payment> payments, Map<WalletNode, Long> changeMap, long fee, Map<Sha256Hash, BlockTransaction> inputTransactions) {
        this.wallet = wallet;
        this.transaction = transaction;
        this.utxoSelectors = utxoSelectors;
        this.selectedUtxoSets = selectedUtxoSets;
        this.payments = payments;
        this.changeMap = changeMap;
        this.fee = fee;
        this.inputTransactions = inputTransactions;
    }

    public PSBT createPSBT() {
        return new PSBT(this);
    }

    public Wallet getWallet() {
        return wallet;
    }

    public Transaction getTransaction() {
        return transaction;
    }

    public List<UtxoSelector> getUtxoSelectors() {
        return utxoSelectors;
    }

    public Map<BlockTransactionHashIndex, WalletNode> getSelectedUtxos() {
        if(selectedUtxoSets.size() == 1) {
            return selectedUtxoSets.get(0);
        }

        Map<BlockTransactionHashIndex, WalletNode> selectedUtxos = new LinkedHashMap<>();
        selectedUtxoSets.forEach(selectedUtxos::putAll);
        return selectedUtxos;
    }

    public List<Map<BlockTransactionHashIndex, WalletNode>> getSelectedUtxoSets() {
        return selectedUtxoSets;
    }

    public List<Payment> getPayments() {
        return payments;
    }

    public Map<WalletNode, Long> getChangeMap() {
        return changeMap;
    }

    public Address getChangeAddress(WalletNode changeNode) {
        return getWallet().getAddress(changeNode);
    }

    public long getFee() {
        return fee;
    }

    public double getFeeRate() {
        return (double)fee / transaction.getVirtualSize();
    }

    public long getTotal() {
        return getSelectedUtxos().keySet().stream().mapToLong(BlockTransactionHashIndex::getValue).sum();
    }

    public Map<Sha256Hash, BlockTransaction> getInputTransactions() {
        return inputTransactions;
    }

    /**
     * Fee percentage matches the Coldcard implementation of total fee as a percentage of total value out
     * @return the fee percentage
     */
    public double getFeePercentage() {
        return getFee() == 0 ? 0 : (double)getFee() / (getTotal() - getFee());
    }

    public boolean isCoinControlUsed() {
        return !utxoSelectors.isEmpty() && utxoSelectors.get(0) instanceof PresetUtxoSelector;
    }

    public boolean isConsolidationSend(Payment payment) {
        return isWalletSend(getWallet(), payment);
    }

    public boolean isPremixSend(Payment payment) {
        return isWalletSend(StandardAccount.WHIRLPOOL_PREMIX, payment);
    }

    public boolean isBadbankSend(Payment payment) {
        return isWalletSend(StandardAccount.WHIRLPOOL_BADBANK, payment);
    }

    private boolean isWalletSend(StandardAccount childAccount, Payment payment) {
        if(getWallet() != null) {
            return isWalletSend(getWallet().getChildWallet(childAccount), payment);
        }

        return false;
    }

    public boolean isWalletSend(Wallet wallet, Payment payment) {
        if(payment.getAddress() != null && wallet != null) {
            return wallet.isWalletOutputScript(payment.getAddress().getOutputScript());
        }

        return false;
    }

    public List<WalletNode> getConsolidationSendNodes() {
        List<WalletNode> walletNodes = new ArrayList<>();
        for(Payment payment : payments) {
            if(payment.getAddress() != null && getWallet() != null) {
                WalletNode walletNode = getWallet().getWalletOutputScripts().get(payment.getAddress().getOutputScript());
                if(walletNode != null) {
                    walletNodes.add(walletNode);
                }
            }
        }

        return walletNodes;
    }
}
