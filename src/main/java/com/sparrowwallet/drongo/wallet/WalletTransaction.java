package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.protocol.Script;
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

    private Map<Wallet, Map<Address, WalletNode>> addressNodeMap = new HashMap<>();

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
        return changeNode.getAddress();
    }

    public long getFee() {
        return fee;
    }

    public double getFeeRate() {
        return (double)fee / transaction.getVirtualSize();
    }

    public long getTotal() {
        return inputAmountsValid() ? getSelectedUtxos().keySet().stream().mapToLong(BlockTransactionHashIndex::getValue).sum() : 0;
    }

    private boolean inputAmountsValid() {
        return getSelectedUtxos().keySet().stream().allMatch(ref -> ref.getValue() > 0);
    }

    public Map<Sha256Hash, BlockTransaction> getInputTransactions() {
        return inputTransactions;
    }

    /**
     * Fee percentage matches the Coldcard implementation of total fee as a percentage of total value out
     * @return the fee percentage
     */
    public double getFeePercentage() {
        return getFee() <= 0 || getTotal() <= 0 ? 0 : (double)getFee() / (getTotal() - getFee());
    }

    public boolean isCoinControlUsed() {
        return !utxoSelectors.isEmpty() && utxoSelectors.get(0) instanceof PresetUtxoSelector;
    }

    public boolean isTwoPersonCoinjoin() {
        return !utxoSelectors.isEmpty() && utxoSelectors.get(0) instanceof StonewallUtxoSelector;
    }

    public boolean isConsolidationSend(Payment payment) {
        return isWalletSend(getWallet(), payment);
    }

    public boolean isPremixSend(Payment payment) {
        return isWalletSend(StandardAccount.WHIRLPOOL_PREMIX, payment);
    }

    public boolean isPostmixSend(Payment payment) {
        return isWalletSend(StandardAccount.WHIRLPOOL_POSTMIX, payment);
    }

    public boolean isBadbankSend(Payment payment) {
        return isWalletSend(StandardAccount.WHIRLPOOL_BADBANK, payment);
    }

    private boolean isWalletSend(StandardAccount childAccount, Payment payment) {
        if(getWallet() != null) {
            Wallet masterWallet = getWallet().isMasterWallet() ? getWallet() : getWallet().getMasterWallet();
            return isWalletSend(masterWallet.getChildWallet(childAccount), payment);
        }

        return false;
    }

    public boolean isWalletSend(Wallet wallet, Payment payment) {
        if(wallet == null) {
            return false;
        }

        return getAddressNodeMap(wallet).get(payment.getAddress()) != null;
    }

    public void updateAddressNodeMap(Map<Wallet, Map<Address, WalletNode>> addressNodeMap, Wallet wallet) {
        this.addressNodeMap = addressNodeMap;
        getAddressNodeMap(wallet);
    }

    public Map<Address, WalletNode> getAddressNodeMap() {
        return getAddressNodeMap(getWallet());
    }

    public Map<Address, WalletNode> getAddressNodeMap(Wallet wallet) {
        Map<Address, WalletNode> walletAddresses = null;

        Map<Address, WalletNode> walletAddressNodeMap = addressNodeMap.computeIfAbsent(wallet, w -> new LinkedHashMap<>());
        for(Payment payment : payments) {
            if(walletAddressNodeMap.containsKey(payment.getAddress())) {
                continue;
            }

            if(payment.getAddress() != null && wallet != null) {
                if(walletAddresses == null) {
                    walletAddresses = wallet.getWalletAddresses();
                }

                WalletNode walletNode = walletAddresses.get(payment.getAddress());
                walletAddressNodeMap.put(payment.getAddress(), walletNode);
            }
        }

        return walletAddressNodeMap;
    }
}
