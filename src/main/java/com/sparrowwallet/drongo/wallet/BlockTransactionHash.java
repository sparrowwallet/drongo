package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.util.Date;
import java.util.Objects;

public abstract class BlockTransactionHash extends Persistable {
    public static final int BLOCKS_TO_CONFIRM = 6;
    public static final int BLOCKS_TO_FULLY_CONFIRM = 100;

    private final Sha256Hash hash;
    private final int height;
    private final Date date;
    private final Long fee;

    private String label;

    public BlockTransactionHash(Sha256Hash hash, int height, Date date, Long fee, String label) {
        this.hash = hash;
        this.height = height;
        this.date = date;
        this.fee = fee;
        this.label = label;
    }

    public Sha256Hash getHash() {
        return hash;
    }

    public String getHashAsString() {
        return hash.toString();
    }

    public int getHeight() {
        return height;
    }

    /**
     * Calculates a special height value that places txes with unconfirmed parents first, then normal unconfirmed txes, then confirmed txes
     *
     * @return the modified height value
     */
    public int getComparisonHeight() {
        return (getHeight() > 0 ? getHeight() : (getHeight() == -1 ? Integer.MAX_VALUE : Integer.MAX_VALUE - getHeight() - 1));
    }

    public int getConfirmations(int currentBlockHeight) {
        if(height <= 0) {
            return 0;
        }

        return currentBlockHeight - height + 1;
    }

    public Date getDate() {
        return date;
    }

    public Long getFee() {
        return fee;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    @Override
    public String toString() {
        return hash.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BlockTransactionHash that = (BlockTransactionHash) o;
        return hash.equals(that.hash) && height == that.height;
    }

    @Override
    public int hashCode() {
        return Objects.hash(hash, height);
    }

    public int compareTo(BlockTransactionHash reference) {
        if(height != reference.height) {
            return getComparisonHeight() - reference.getComparisonHeight();
        }

        return hash.compareTo(reference.hash);
    }
}
