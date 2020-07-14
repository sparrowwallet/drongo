package com.sparrowwallet.drongo.wallet;

import java.util.Collection;
import java.util.stream.Collectors;

public class MaxUtxoSelector implements UtxoSelector {
    @Override
    public Collection<BlockTransactionHashIndex> select(long targetValue, Collection<OutputGroup> candidates) {
        return candidates.stream().flatMap(outputGroup -> outputGroup.getUtxos().stream()).collect(Collectors.toUnmodifiableList());
    }
}
