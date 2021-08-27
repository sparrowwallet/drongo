package com.sparrowwallet.drongo.wallet;

import java.util.Collection;
import java.util.List;

public abstract class SingleSetUtxoSelector implements UtxoSelector {
    @Override
    public List<Collection<BlockTransactionHashIndex>> selectSets(long targetValue, Collection<OutputGroup> candidates) {
        return List.of(select(targetValue, candidates));
    }

    public abstract Collection<BlockTransactionHashIndex> select(long targetValue, Collection<OutputGroup> candidates);
}
