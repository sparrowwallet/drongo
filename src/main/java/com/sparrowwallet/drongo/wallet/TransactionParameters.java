package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.protocol.Transaction;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public record TransactionParameters(List<UtxoSelector> utxoSelectors, List<TxoFilter> txoFilters, List<Payment> payments, List<byte[]> opReturns,
                                    Set<WalletNode> excludedChangeNodes, double feeRate, double longTermFeeRate, double minRelayFeeRate, Long fee,
                                    Integer currentBlockHeight, boolean groupByAddress, boolean includeMempoolOutputs, boolean allowRbf) {

    public boolean containsSendMaxPayment() {
        return payments.stream().anyMatch(Payment::isSendMax);
    }

    public Optional<Payment> getFirstSendMaxPayment() {
        return payments.stream().filter(Payment::isSendMax).findFirst();
    }

    public List<Address> getPaymentAddresses() {
        return payments.stream().map(Payment::getAddress).toList();
    }

    public long getTotalPaymentAmount() {
        return payments.stream().mapToLong(Payment::getAmount).sum();
    }

    public long getTotalPaymentAmountLessExcluded(Payment excludedPayment) {
        return payments.stream().filter(payment -> !excludedPayment.equals(payment)).mapToLong(Payment::getAmount).sum();
    }

    public boolean isMinRelayRate() {
        return ((feeRate == minRelayFeeRate && minRelayFeeRate > 0d) || feeRate == Transaction.DEFAULT_MIN_RELAY_FEE) && fee == null;
    }

    public long getRequiredFeeAmount(double virtualSize) {
        return fee == null ? (long)Math.floor(feeRate * virtualSize) : fee;
    }
}
