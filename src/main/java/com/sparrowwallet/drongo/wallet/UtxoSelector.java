package com.sparrowwallet.drongo.wallet;

import java.util.Collection;
import java.util.List;

public interface UtxoSelector {
    List<Collection<BlockTransactionHashIndex>> selectSets(long targetValue, Collection<OutputGroup> candidates);
    default boolean shuffleInputs() {
        return true;
    }
}
