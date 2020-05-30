package com.sparrowwallet.drongo.wallet;

import java.util.Objects;

public class TransactionReference implements Comparable<TransactionReference> {
    private final String transactionId;
    private final Integer height;
    private final Long fee;

    public TransactionReference(String transactionId) {
        this(transactionId, 0, 0L);
    }

    public TransactionReference(String transactionId, Integer height) {
        this(transactionId, height, 0L);
    }

    public TransactionReference(String transactionId, Integer height, Long fee) {
        this.transactionId = transactionId;
        this.height = height;
        this.fee = fee;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public Integer getHeight() {
        return height;
    }

    public Long getFee() {
        return fee;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TransactionReference that = (TransactionReference) o;
        return transactionId.equals(that.transactionId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(transactionId);
    }

    @Override
    public int compareTo(TransactionReference reference) {
        return height - reference.height;
    }

    public TransactionReference copy() {
        return new TransactionReference(transactionId, height, fee);
    }
}
