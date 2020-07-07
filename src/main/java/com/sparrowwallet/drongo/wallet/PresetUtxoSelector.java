package com.sparrowwallet.drongo.wallet;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class PresetUtxoSelector implements UtxoSelector {
    private final Collection<BlockTransactionHashIndex> presetUtxos;

    public PresetUtxoSelector(Collection<BlockTransactionHashIndex> presetUtxos) {
        this.presetUtxos = presetUtxos;
    }

    @Override
    public Collection<BlockTransactionHashIndex> select(long targetValue, Collection<BlockTransactionHashIndex> candidates) {
        List<BlockTransactionHashIndex> utxos = new ArrayList<>(presetUtxos);
        utxos.retainAll(candidates);

        return utxos;
    }

    public Collection<BlockTransactionHashIndex> getPresetUtxos() {
        return presetUtxos;
    }
}
