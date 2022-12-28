package com.sparrowwallet.drongo.wallet;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class PresetUtxoSelector extends SingleSetUtxoSelector {
    private final Collection<BlockTransactionHashIndex> presetUtxos;
    private final boolean maintainOrder;

    public PresetUtxoSelector(Collection<BlockTransactionHashIndex> presetUtxos) {
        this.presetUtxos = presetUtxos;
        this.maintainOrder = false;
    }

    public PresetUtxoSelector(Collection<BlockTransactionHashIndex> presetUtxos, boolean maintainOrder) {
        this.presetUtxos = presetUtxos;
        this.maintainOrder = maintainOrder;
    }

    @Override
    public Collection<BlockTransactionHashIndex> select(long targetValue, Collection<OutputGroup> candidates) {
        List<BlockTransactionHashIndex> flattenedCandidates = candidates.stream().flatMap(outputGroup -> outputGroup.getUtxos().stream()).collect(Collectors.toList());
        List<BlockTransactionHashIndex> utxos = new ArrayList<>();

        //Don't use equals() here as we don't want to consider height which may change as txes are confirmed
        for(BlockTransactionHashIndex candidate : flattenedCandidates) {
            for(BlockTransactionHashIndex presetUtxo : presetUtxos) {
                if(candidate.getHash().equals(presetUtxo.getHash()) && candidate.getIndex() == presetUtxo.getIndex()) {
                    utxos.add(candidate);
                }
            }
        }

        if(maintainOrder && utxos.containsAll(presetUtxos)) {
            return presetUtxos;
        }

        return utxos;
    }

    public Collection<BlockTransactionHashIndex> getPresetUtxos() {
        return presetUtxos;
    }

    @Override
    public boolean shuffleInputs() {
        return !maintainOrder;
    }
}
