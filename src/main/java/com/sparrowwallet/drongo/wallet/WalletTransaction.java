package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.psbt.PSBT;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * WalletTransaction contains a draft transaction along with associated metadata. The draft transaction has empty signatures but is otherwise complete.
 * This object represents an intermediate step before the transaction is signed or a PSBT is created from it.
 */
public class WalletTransaction {
    private final Wallet wallet;
    private final Transaction transaction;
    private final List<UtxoSelector> utxoSelectors;
    private final Map<BlockTransactionHashIndex, WalletNode> selectedUtxos;
    private final List<Payment> payments;
    private final WalletNode changeNode;
    private final long changeAmount;
    private final long fee;

    public WalletTransaction(Wallet wallet, Transaction transaction, List<UtxoSelector> utxoSelectors, Map<BlockTransactionHashIndex, WalletNode> selectedUtxos, List<Payment> payments, long fee) {
        this(wallet, transaction, utxoSelectors, selectedUtxos, payments, null, 0L, fee);
    }

    public WalletTransaction(Wallet wallet, Transaction transaction, List<UtxoSelector> utxoSelectors, Map<BlockTransactionHashIndex, WalletNode> selectedUtxos, List<Payment> payments, WalletNode changeNode, long changeAmount, long fee) {
        this.wallet = wallet;
        this.transaction = transaction;
        this.utxoSelectors = utxoSelectors;
        this.selectedUtxos = selectedUtxos;
        this.payments = payments;
        this.changeNode = changeNode;
        this.changeAmount = changeAmount;
        this.fee = fee;
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
        return selectedUtxos;
    }

    public List<Payment> getPayments() {
        return payments;
    }

    public WalletNode getChangeNode() {
        return changeNode;
    }

    public Address getChangeAddress() {
        return getWallet().getAddress(getChangeNode());
    }

    public long getChangeAmount() {
        return changeAmount;
    }

    public long getFee() {
        return fee;
    }

    public double getFeeRate() {
        return (double)fee / transaction.getVirtualSize();
    }

    public long getTotal() {
        return selectedUtxos.keySet().stream().mapToLong(BlockTransactionHashIndex::getValue).sum();
    }

    /**
     * Fee percentage matches the Coldcard implementation of total fee as a percentage of total value out
     * @return the fee percentage
     */
    public double getFeePercentage() {
        return (double)getFee() / (getTotal() - getFee());
    }

    public boolean isCoinControlUsed() {
        return !utxoSelectors.isEmpty() && utxoSelectors.get(0) instanceof PresetUtxoSelector;
    }

    public boolean isConsolidationSend(Payment payment) {
        return isWalletSend(getWallet(), payment);
    }

    public boolean isPremixSend(Payment payment) {
        return isWalletSend(getWallet().getChildWallet(StandardAccount.WHIRLPOOL_PREMIX), payment);
    }

    public boolean isBadbankSend(Payment payment) {
        return isWalletSend(getWallet().getChildWallet(StandardAccount.WHIRLPOOL_BADBANK), payment);
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
