package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

public class SpentTxoFilter implements TxoFilter {
    private final Sha256Hash replacedTxid;

    public SpentTxoFilter() {
        replacedTxid = null;
    }

    public SpentTxoFilter(Sha256Hash replacedTxid) {
        this.replacedTxid = replacedTxid;
    }

    @Override
    public boolean isEligible(BlockTransactionHashIndex candidate) {
        return !isSpentOrReplaced(candidate);
    }

    private boolean isSpentOrReplaced(BlockTransactionHashIndex candidate) {
        return candidate.getHash().equals(replacedTxid) || (candidate.isSpent() && !candidate.getSpentBy().getHash().equals(replacedTxid));
    }
}
