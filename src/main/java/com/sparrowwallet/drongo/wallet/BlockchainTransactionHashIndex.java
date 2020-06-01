package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.util.Objects;

public class BlockchainTransactionHashIndex extends BlockchainTransactionHash {
    private final long index;
    private final BlockchainTransactionHashIndex spentBy;

    public BlockchainTransactionHashIndex(Sha256Hash hash, Integer height, Long fee, long index) {
        this(hash, height, fee, index, null);
    }

    public BlockchainTransactionHashIndex(Sha256Hash hash, Integer height, Long fee, long index, BlockchainTransactionHashIndex spentBy) {
        super(hash, height, fee);
        this.index = index;
        this.spentBy = spentBy;
    }

    public long getIndex() {
        return index;
    }

    public boolean isSpent() {
        return spentBy != null;
    }

    public BlockchainTransactionHashIndex getSpentBy() {
        return spentBy;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        BlockchainTransactionHashIndex that = (BlockchainTransactionHashIndex) o;
        return index == that.index &&
                Objects.equals(spentBy, that.spentBy);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), index, spentBy);
    }
}
