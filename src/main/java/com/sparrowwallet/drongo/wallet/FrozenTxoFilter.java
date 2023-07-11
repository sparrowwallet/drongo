package com.sparrowwallet.drongo.wallet;

public class FrozenTxoFilter implements TxoFilter {
    @Override
    public boolean isEligible(BlockTransactionHashIndex candidate) {
        return candidate.getStatus() == null || candidate.getStatus() != Status.FROZEN;
    }
}
