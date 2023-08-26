package com.sparrowwallet.drongo.wallet;

public interface TxoFilter {
    boolean isEligible(BlockTransactionHashIndex candidate);
}
