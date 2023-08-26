package com.sparrowwallet.drongo.wallet;

import java.util.ArrayList;
import java.util.Collection;

public class ExcludeTxoFilter implements TxoFilter {
    private final Collection<BlockTransactionHashIndex> excludedTxos;

    public ExcludeTxoFilter() {
        this.excludedTxos = new ArrayList<>();
    }

    public ExcludeTxoFilter(Collection<BlockTransactionHashIndex> excludedTxos) {
        this.excludedTxos = new ArrayList<>(excludedTxos);
    }

    @Override
    public boolean isEligible(BlockTransactionHashIndex candidate) {
        for(BlockTransactionHashIndex excludedTxo : excludedTxos) {
            if(candidate.getHash().equals(excludedTxo.getHash()) && candidate.getIndex() == excludedTxo.getIndex()) {
                return false;
            }
        }

        return true;
    }

    public Collection<BlockTransactionHashIndex> getExcludedTxos() {
        return excludedTxos;
    }
}
