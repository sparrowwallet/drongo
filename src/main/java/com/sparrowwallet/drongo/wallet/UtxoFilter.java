package com.sparrowwallet.drongo.wallet;

public interface UtxoFilter {
    boolean isEligible(BlockTransactionHashIndex candidate);
}
