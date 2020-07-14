package com.sparrowwallet.drongo.wallet;

import java.util.Collection;

public interface UtxoSelector {
    Collection<BlockTransactionHashIndex> select(long targetValue, Collection<OutputGroup> candidates);
}
