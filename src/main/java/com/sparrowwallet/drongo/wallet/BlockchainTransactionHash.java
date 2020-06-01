package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.util.Objects;

public class BlockchainTransactionHash implements Comparable<BlockchainTransactionHash> {
    private final Sha256Hash hash;
    private final Integer height;
    private final Long fee;

    public BlockchainTransactionHash(Sha256Hash hash) {
        this(hash, 0, 0L);
    }

    public BlockchainTransactionHash(Sha256Hash hash, Integer height) {
        this(hash, height, 0L);
    }

    public BlockchainTransactionHash(Sha256Hash hash, Integer height, Long fee) {
        this.hash = hash;
        this.height = height;
        this.fee = fee;
    }

    public Sha256Hash getHash() {
        return hash;
    }

    public String getHashAsString() {
        return hash.toString();
    }

    public Integer getHeight() {
        return height;
    }

    public Long getFee() {
        return fee;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BlockchainTransactionHash that = (BlockchainTransactionHash) o;
        return hash.equals(that.hash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hash);
    }

    @Override
    public int compareTo(BlockchainTransactionHash reference) {
        return height - reference.height;
    }

    public BlockchainTransactionHash copy() {
        return new BlockchainTransactionHash(hash, height, fee);
    }
}
