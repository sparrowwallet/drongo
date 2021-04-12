package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class BlockTransaction extends BlockTransactionHash implements Comparable<BlockTransaction> {
    private final Transaction transaction;
    private final Sha256Hash blockHash;

    public BlockTransaction(Sha256Hash hash, int height, Date date, Long fee, Transaction transaction) {
        this(hash, height, date, fee, transaction, null);
    }

    public BlockTransaction(Sha256Hash hash, int height, Date date, Long fee, Transaction transaction, Sha256Hash blockHash) {
        this(hash, height, date, fee, transaction, blockHash, null);
    }

    public BlockTransaction(Sha256Hash hash, int height, Date date, Long fee, Transaction transaction, Sha256Hash blockHash, String label) {
        super(hash, height, date, fee, label);
        this.transaction = transaction;
        this.blockHash = blockHash;
    }

    public Transaction getTransaction() {
        return transaction;
    }

    public Sha256Hash getBlockHash() {
        return blockHash;
    }

    @Override
    public int compareTo(BlockTransaction blkTx) {
        int blockOrder = compareBlockOrder(blkTx);
        if(blockOrder != 0) {
            return blockOrder;
        }

        return super.compareTo(blkTx);
    }

    public int compareBlockOrder(BlockTransaction blkTx) {
        if(getHeight() != blkTx.getHeight()) {
            return getComparisonHeight() - blkTx.getComparisonHeight();
        }

        if(getReferencedOutpoints(this).removeAll(getOutputs(blkTx))) {
            return 1;
        }

        if(getReferencedOutpoints(blkTx).removeAll(getOutputs(this))) {
            return -1;
        }

        return 0;
    }

    private static List<HashIndex> getReferencedOutpoints(BlockTransaction blockchainTransaction) {
        if(blockchainTransaction.getTransaction() == null) {
            return Collections.emptyList();
        }

        return blockchainTransaction.getTransaction().getInputs().stream()
                .map(txInput -> new HashIndex(txInput.getOutpoint().getHash(), (int)txInput.getOutpoint().getIndex()))
                .collect(Collectors.toList());
    }

    private static List<HashIndex> getOutputs(BlockTransaction blockchainTransaction) {
        if(blockchainTransaction.getTransaction() == null) {
            return Collections.emptyList();
        }

        return blockchainTransaction.getTransaction().getOutputs().stream()
                .map(txOutput -> new HashIndex(blockchainTransaction.getHash(), txOutput.getIndex()))
                .collect(Collectors.toList());
    }

    private static class HashIndex {
        public Sha256Hash hash;
        public int index;

        public HashIndex(Sha256Hash hash, int index) {
            this.hash = hash;
            this.index = index;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            HashIndex hashIndex = (HashIndex) o;
            return index == hashIndex.index &&
                    hash.equals(hashIndex.hash);
        }

        @Override
        public int hashCode() {
            return Objects.hash(hash, index);
        }
    }
}
