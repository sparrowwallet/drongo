package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;

import java.util.Date;

public class BlockTransaction extends BlockTransactionHash implements Comparable<BlockTransaction> {
    private final Transaction transaction;
    private final Sha256Hash blockHash;

    public BlockTransaction(Sha256Hash hash, int height, Date date, Long fee, Transaction transaction) {
        this(hash, height, date, fee, transaction, null);
    }

    public BlockTransaction(Sha256Hash hash, int height, Date date, Long fee, Transaction transaction, Sha256Hash blockHash) {
        super(hash, height, date, fee);
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
    public int compareTo(BlockTransaction blockchainTransaction) {
        return super.compareTo(blockchainTransaction);
    }
}
