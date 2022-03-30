package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.ScriptType;

import java.util.*;
import java.util.stream.Collectors;

public class StonewallUtxoSelector implements UtxoSelector {
    private final ScriptType preferredScriptType;
    private final long noInputsFee;

    //Use the same seed so the UTXO selection is deterministic
    private final Random random = new Random(42);

    public StonewallUtxoSelector(ScriptType preferredScriptType, long noInputsFee) {
        this.preferredScriptType = preferredScriptType;
        this.noInputsFee = noInputsFee;
    }

    @Override
    public List<Collection<BlockTransactionHashIndex>> selectSets(long targetValue, Collection<OutputGroup> candidates) {
        long actualTargetValue = targetValue + noInputsFee;

        List<OutputGroup> uniqueCandidates = new ArrayList<>();
        for(OutputGroup candidate : candidates) {
            OutputGroup existingTxGroup = getTransactionAlreadySelected(uniqueCandidates, candidate);
            if(existingTxGroup != null) {
                if(candidate.getValue() > existingTxGroup.getValue()) {
                    uniqueCandidates.remove(existingTxGroup);
                    uniqueCandidates.add(candidate);
                }
            } else {
                uniqueCandidates.add(candidate);
            }
        }

        List<OutputGroup> preferredCandidates = uniqueCandidates.stream().filter(outputGroup -> outputGroup.getScriptType().equals(preferredScriptType)).collect(Collectors.toList());
        List<Collection<BlockTransactionHashIndex>> preferredSets = selectSets(targetValue, preferredCandidates, actualTargetValue);
        if(!preferredSets.isEmpty()) {
            return preferredSets;
        }

        return selectSets(targetValue, uniqueCandidates, actualTargetValue);
    }

    private List<Collection<BlockTransactionHashIndex>> selectSets(long targetValue, List<OutputGroup> uniqueCandidates, long actualTargetValue) {
        for(int i = 0; i < 15; i++) {
            List<OutputGroup> randomized = new ArrayList<>(uniqueCandidates);
            Collections.shuffle(randomized, random);

            List<OutputGroup> set1 = new ArrayList<>();
            long selectedValue1 = getUtxoSet(actualTargetValue, set1, randomized);

            List<OutputGroup> set2 = new ArrayList<>();
            long selectedValue2 = getUtxoSet(actualTargetValue, set2, randomized);

            if(selectedValue1 >= targetValue && selectedValue2 >= targetValue) {
                return List.of(getUtxos(set1), getUtxos(set2));
            }
        }

        return Collections.emptyList();
    }

    private long getUtxoSet(long targetValue, List<OutputGroup> selectedSet, List<OutputGroup> randomized) {
        long selectedValue = 0;
        while(selectedValue <= targetValue && !randomized.isEmpty()) {
            OutputGroup candidate = randomized.remove(0);
            selectedSet.add(candidate);
            selectedValue = selectedSet.stream().mapToLong(OutputGroup::getEffectiveValue).sum();
        }

        return selectedValue;
    }

    private OutputGroup getTransactionAlreadySelected(List<OutputGroup> selected, OutputGroup candidateGroup) {
        for(OutputGroup selectedGroup : selected) {
            for(BlockTransactionHashIndex selectedUtxo : selectedGroup.getUtxos()) {
                for(BlockTransactionHashIndex candidateUtxo : candidateGroup.getUtxos()) {
                    if(selectedUtxo.getHash().equals(candidateUtxo.getHash())) {
                        return selectedGroup;
                    }
                }
            }
        }

        return null;
    }

    private Collection<BlockTransactionHashIndex> getUtxos(List<OutputGroup> set) {
        return set.stream().flatMap(outputGroup -> outputGroup.getUtxos().stream()).collect(Collectors.toList());
    }
}
