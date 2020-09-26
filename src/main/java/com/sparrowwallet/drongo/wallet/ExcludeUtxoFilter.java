package com.sparrowwallet.drongo.wallet;

import java.util.ArrayList;
import java.util.Collection;

public class ExcludeUtxoFilter implements UtxoFilter {
    private final Collection<BlockTransactionHashIndex> excludedUtxos;

    public ExcludeUtxoFilter() {
        this.excludedUtxos = new ArrayList<>();
    }

    public ExcludeUtxoFilter(Collection<BlockTransactionHashIndex> excludedUtxos) {
        this.excludedUtxos = new ArrayList<>(excludedUtxos);
    }

    @Override
    public boolean isEligible(BlockTransactionHashIndex candidate) {
        for(BlockTransactionHashIndex excludedUtxo : excludedUtxos) {
            if(candidate.getHash().equals(excludedUtxo.getHash()) && candidate.getIndex() == excludedUtxo.getIndex()) {
                return false;
            }
        }

        return true;
    }

    public Collection<BlockTransactionHashIndex> getExcludedUtxos() {
        return excludedUtxos;
    }
}
