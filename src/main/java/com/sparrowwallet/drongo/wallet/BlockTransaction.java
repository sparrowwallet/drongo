package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.*;

import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class BlockTransaction extends BlockTransactionHash implements Comparable<BlockTransaction> {
    private final Transaction transaction;
    private final Sha256Hash blockHash;

    private final Set<HashIndex> spending = new HashSet<>();
    private final Set<HashIndex> funding = new HashSet<>();

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

        if(transaction != null) {
            for(TransactionInput txInput : transaction.getInputs()) {
                spending.add(new HashIndex(txInput.getOutpoint().getHash(), txInput.getOutpoint().getIndex()));
            }
            for(TransactionOutput txOutput : transaction.getOutputs()) {
                funding.add(new HashIndex(hash, txOutput.getIndex()));
            }
        }
    }

    public Transaction getTransaction() {
        return transaction;
    }

    public Sha256Hash getBlockHash() {
        return blockHash;
    }

    public Set<HashIndex> getSpending() {
        return Collections.unmodifiableSet(spending);
    }

    public Set<HashIndex> getFunding() {
        return Collections.unmodifiableSet(funding);
    }

    public Double getFeeRate() {
        if(getFee() != null && transaction != null) {
            double vSize = transaction.getVirtualSize();
            return getFee() / vSize;
        }

        return null;
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

        if(!Collections.disjoint(spending, blkTx.funding)) {
            return 1;
        }

        if(!Collections.disjoint(blkTx.spending, funding)) {
            return -1;
        }

        return 0;
    }
}
