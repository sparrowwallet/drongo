package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.protocol.*;
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
    private final List<Output> outputs;

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
        this.outputs = calculateOutputs();

        for(Payment payment : payments) {
            payment.setLabel(getOutputLabel(payment));
        }
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

    public List<Output> getOutputs() {
        return outputs;
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

    private String getOutputLabel(Payment payment) {
        if(payment.getLabel() != null) {
            return payment.getLabel();
        }

        if(payment.getType() == Payment.Type.WHIRLPOOL_FEE) {
            return "Whirlpool fee";
        } else if(isPremixSend(payment)) {
            int premixIndex = getOutputIndex(payment.getAddress(), payment.getAmount(), Collections.emptySet()) - 2;
            return "Premix #" + premixIndex;
        } else if(isBadbankSend(payment)) {
            return "Badbank change";
        }

        return null;
    }

    public int getOutputIndex(Address address, long amount, Collection<Integer> seenIndexes) {
        TransactionOutput output = getTransaction().getOutputs().stream()
                .filter(txOutput -> address.equals(txOutput.getScript().getToAddress()) && txOutput.getValue() == amount && !seenIndexes.contains(txOutput.getIndex()))
                .findFirst().orElseThrow();
        return getTransaction().getOutputs().indexOf(output);
    }

    public Wallet getToWallet(Collection<Wallet> wallets, Payment payment) {
        for(Wallet openWallet : wallets) {
            if(openWallet != getWallet() && openWallet.isValid()) {
                WalletNode addressNode = openWallet.getWalletAddresses().get(payment.getAddress());
                if(addressNode != null) {
                    return addressNode.getWallet();
                }
            }
        }

        return null;
    }

    public boolean isDuplicateAddress(Payment payment) {
        return getPayments().stream().filter(p -> payment != p).anyMatch(p -> payment.getAddress() != null && payment.getAddress().equals(p.getAddress()));
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

    private List<Output> calculateOutputs() {
        List<Output> outputs = new ArrayList<>();

        for(int i = 0, paymentIndex = 0; i < transaction.getOutputs().size(); i++) {
            TransactionOutput txOutput = transaction.getOutputs().get(i);
            Address address = txOutput.getScript().getToAddress();
            if(address == null) {
                outputs.add(new NonAddressOutput(txOutput));
            } else if(paymentIndex < payments.size()) {
                Payment payment = payments.get(paymentIndex++);
                outputs.add(new PaymentOutput(txOutput, payment));
            }
        }

        Set<Integer> seenIndexes = new HashSet<>();
        for(Map.Entry<WalletNode, Long> changeEntry : changeMap.entrySet()) {
            int outputIndex = getOutputIndex(changeEntry.getKey().getAddress(), changeEntry.getValue(), seenIndexes);
            TransactionOutput txOutput = transaction.getOutputs().get(outputIndex);
            seenIndexes.add(outputIndex);
            outputs.add(outputIndex, new ChangeOutput(txOutput, changeEntry.getKey(), changeEntry.getValue()));
        }

        return outputs;
    }

    public static class Output {
        private final TransactionOutput transactionOutput;

        public Output(TransactionOutput transactionOutput) {
            this.transactionOutput = transactionOutput;
        }

        public TransactionOutput getTransactionOutput() {
            return transactionOutput;
        }
    }

    public static class NonAddressOutput extends Output {
        public NonAddressOutput(TransactionOutput transactionOutput) {
            super(transactionOutput);
        }
    }

    public static class PaymentOutput extends Output {
        private final Payment payment;

        public PaymentOutput(TransactionOutput transactionOutput, Payment payment) {
            super(transactionOutput);
            this.payment = payment;
        }

        public Payment getPayment() {
            return payment;
        }
    }

    public static class ChangeOutput extends Output {
        private final WalletNode walletNode;
        private final Long value;

        public ChangeOutput(TransactionOutput transactionOutput, WalletNode walletNode, Long value) {
            super(transactionOutput);
            this.walletNode = walletNode;
            this.value = value;
        }

        public WalletNode getWalletNode() {
            return walletNode;
        }

        public Long getValue() {
            return value;
        }
    }
}
