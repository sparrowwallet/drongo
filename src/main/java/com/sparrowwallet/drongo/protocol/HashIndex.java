package com.sparrowwallet.drongo.protocol;

public class HashIndex {
    private final Sha256Hash hash;
    private final long index;

    public HashIndex(Sha256Hash hash, long index) {
        this.hash = hash;
        this.index = index;
    }

    public Sha256Hash getHash() {
        return hash;
    }

    public long getIndex() {
        return index;
    }

    @Override
    public String toString() {
        return hash.toString() + ":" + index;
    }

    @Override
    public boolean equals(Object o) {
        if(this == o) {
            return true;
        }
        if(o == null || getClass() != o.getClass()) {
            return false;
        }

        HashIndex hashIndex = (HashIndex) o;

        if(index != hashIndex.index) {
            return false;
        }
        return hash.equals(hashIndex.hash);
    }

    @Override
    public int hashCode() {
        int result = hash.hashCode();
        result = 31 * result + (int) (index ^ (index >>> 32));
        return result;
    }
}
