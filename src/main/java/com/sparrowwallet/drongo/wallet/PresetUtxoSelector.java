package com.sparrowwallet.drongo.wallet;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class PresetUtxoSelector implements UtxoSelector {
    private final Collection<BlockTransactionHashIndex> presetUtxos;

    public PresetUtxoSelector(Collection<BlockTransactionHashIndex> presetUtxos) {
        this.presetUtxos = presetUtxos;
    }

    @Override
    public Collection<BlockTransactionHashIndex> select(long targetValue, Collection<OutputGroup> candidates) {
        List<BlockTransactionHashIndex> utxos = new ArrayList<>(presetUtxos);
        utxos.retainAll(candidates.stream().flatMap(outputGroup -> outputGroup.getUtxos().stream()).collect(Collectors.toList()));

        return utxos;
    }

    public Collection<BlockTransactionHashIndex> getPresetUtxos() {
        return presetUtxos;
    }
}
