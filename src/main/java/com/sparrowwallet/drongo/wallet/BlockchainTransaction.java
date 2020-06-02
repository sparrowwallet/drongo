package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;

public class BlockchainTransaction extends BlockchainTransactionHash implements Comparable<BlockchainTransaction> {
    private final Transaction transaction;

    public BlockchainTransaction(Sha256Hash hash, int height, Long fee, Transaction transaction) {
        super(hash, height, fee);
        this.transaction = transaction;
    }

    public Transaction getTransaction() {
        return transaction;
    }

    @Override
    public int compareTo(BlockchainTransaction blockchainTransaction) {
        return super.compareTo(blockchainTransaction);
    }
}
