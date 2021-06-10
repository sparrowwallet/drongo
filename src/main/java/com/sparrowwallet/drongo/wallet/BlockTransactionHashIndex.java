package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.util.Date;
import java.util.Objects;

public class BlockTransactionHashIndex extends BlockTransactionHash implements Comparable<BlockTransactionHashIndex> {
    private final long index;
    private final long value;
    private BlockTransactionHashIndex spentBy;
    private Status status;

    public BlockTransactionHashIndex(Sha256Hash hash, int height, Date date, Long fee, long index, long value) {
        this(hash, height, date, fee, index, value, null);
    }

    public BlockTransactionHashIndex(Sha256Hash hash, int height, Date date, Long fee, long index, long value, BlockTransactionHashIndex spentBy) {
        this(hash, height, date, fee, index, value, spentBy, null);
    }

    public BlockTransactionHashIndex(Sha256Hash hash, int height, Date date, Long fee, long index, long value, BlockTransactionHashIndex spentBy, String label) {
        super(hash, height, date, fee, label);
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

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
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
        return index == that.index &&
                value == that.value &&
                Objects.equals(spentBy, that.spentBy);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), index, value, spentBy);
    }

    @Override
    public int compareTo(BlockTransactionHashIndex reference) {
        int diff = super.compareTo(reference);
        if(diff != 0) {
            return diff;
        }

        diff = (int)(index - reference.index);
        if(diff != 0) {
            return diff;
        }

        diff = (int)(value - reference.value);
        if(diff != 0) {
            return diff;
        }

        return spentBy == null ? (reference.spentBy == null ? 0 : Integer.MIN_VALUE) : (reference.spentBy == null ? Integer.MAX_VALUE : spentBy.compareTo(reference.spentBy));
    }

    public BlockTransactionHashIndex copy() {
        BlockTransactionHashIndex copy = new BlockTransactionHashIndex(super.getHash(), super.getHeight(), super.getDate(), super.getFee(), index, value, spentBy == null ? null : spentBy.copy(), super.getLabel());
        copy.setId(getId());
        return copy;
    }
}
