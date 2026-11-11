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
     * Calculates a special height value that, in ascending order, places confirmed txes first, then normal unconfirmed txes, then txes with unconfirmed parents
     *
     * @param height the block height, 0 for an unconfirmed tx or -1 for a tx with unconfirmed parents
     * @return the modified height value
     */
    private static long getComparisonHeight(int height) {
        return (height > 0 ? height : (height == -1 ? Integer.MAX_VALUE : (long)Integer.MAX_VALUE - height - 1));
    }

    /**
     * Orders by comparison height, falling back to the height itself so that references at different heights never compare as equal
     *
     * @param reference the reference to compare against
     * @return the height order of this reference relative to the given reference
     */
    public int compareHeight(BlockTransactionHash reference) {
        int order = Long.compare(getComparisonHeight(getHeight()), getComparisonHeight(reference.getHeight()));
        return order != 0 ? order : Integer.compare(getHeight(), reference.getHeight());
    }

    public int getConfirmations(int currentBlockHeight) {
        if(height <= 0) {
            return 0;
        }

        //A block above the current tip is not in the chain being followed, so a transaction recorded there has no confirmations until its history is refreshed
        return Math.max(0, currentBlockHeight - height + 1);
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
        if(this == o) {
            return true;
        }
        if(o == null || getClass() != o.getClass()) {
            return false;
        }
        BlockTransactionHash that = (BlockTransactionHash)o;
        return hash.equals(that.hash) && height == that.height;
    }

    @Override
    public int hashCode() {
        return Objects.hash(hash, height);
    }

    public int compareTo(BlockTransactionHash reference) {
        if(height != reference.height) {
            return compareHeight(reference);
        }

        return hash.compareTo(reference.hash);
    }
}
