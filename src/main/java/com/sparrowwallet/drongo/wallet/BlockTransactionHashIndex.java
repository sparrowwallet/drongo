package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.util.Objects;

public class BlockTransactionHashIndex extends BlockTransactionHash implements Comparable<BlockTransactionHashIndex> {
    private final long index;
    private final long value;
    private BlockTransactionHashIndex spentBy;

    public BlockTransactionHashIndex(Sha256Hash hash, int height, Long fee, long index, long value) {
        this(hash, height, fee, index, value, null);
    }

    public BlockTransactionHashIndex(Sha256Hash hash, int height, Long fee, long index, long value, BlockTransactionHashIndex spentBy) {
        super(hash, height, fee);
        this.index = index;
        this.value = value;
        this.spentBy = spentBy;
    }

    public long getIndex() {
        return index;
    }

    public long getValue() {
        return value;
    }

    public boolean isSpent() {
        return spentBy != null;
    }

    public BlockTransactionHashIndex getSpentBy() {
        return spentBy;
    }

    public void setSpentBy(BlockTransactionHashIndex spentBy) {
        this.spentBy = spentBy;
    }

    @Override
    public String toString() {
        return getHash().toString() + ":" + index;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        BlockTransactionHashIndex that = (BlockTransactionHashIndex) o;
        return index == that.index;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), index);
    }

    @Override
    public int compareTo(BlockTransactionHashIndex reference) {
        int diff = super.compareTo(reference);
        if(diff != 0) {
            return diff;
        }

        return (int)(index - reference.index);
    }

    public BlockTransactionHashIndex copy() {
        return new BlockTransactionHashIndex(super.getHash(), super.getHeight(), super.getFee(), index, value, spentBy.copy());
    }
}
