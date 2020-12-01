package com.sparrowwallet.drongo.wallet;

public class FrozenUtxoFilter implements UtxoFilter {
    @Override
    public boolean isEligible(BlockTransactionHashIndex candidate) {
        return candidate.getStatus() == null || candidate.getStatus() != Status.FROZEN;
    }
}
