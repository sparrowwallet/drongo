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

        return utxos;
    }

    public Collection<BlockTransactionHashIndex> getPresetUtxos() {
        return presetUtxos;
    }
}
