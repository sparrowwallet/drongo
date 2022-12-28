package com.sparrowwallet.drongo.wallet;

import java.util.Collection;
import java.util.stream.Collectors;

public class MaxUtxoSelector extends SingleSetUtxoSelector {
    @Override
    public Collection<BlockTransactionHashIndex> select(long targetValue, Collection<OutputGroup> candidates) {
        return candidates.stream().filter(outputGroup -> outputGroup.getEffectiveValue() >= 0).flatMap(outputGroup -> outputGroup.getUtxos().stream()).collect(Collectors.toUnmodifiableList());
    }
}
