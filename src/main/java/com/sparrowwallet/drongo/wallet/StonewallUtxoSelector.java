package com.sparrowwallet.drongo.wallet;

import java.util.*;
import java.util.stream.Collectors;

public class StonewallUtxoSelector implements UtxoSelector {
    private final long noInputsFee;

    //Use the same seed so the UTXO selection is deterministic
    private final Random random = new Random(42);

    public StonewallUtxoSelector(long noInputsFee) {
        this.noInputsFee = noInputsFee;
    }

    @Override
    public List<Collection<BlockTransactionHashIndex>> selectSets(long targetValue, Collection<OutputGroup> candidates) {
        long actualTargetValue = targetValue + noInputsFee;

        for(int i = 0; i < 10; i++) {
            List<OutputGroup> randomized = new ArrayList<>(candidates);
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

            OutputGroup existingTxGroup = getTransactionAlreadySelected(selectedSet, candidate);
            if(existingTxGroup != null) {
                if(candidate.getValue() > existingTxGroup.getValue()) {
                    selectedSet.remove(existingTxGroup);
                    selectedSet.add(candidate);
                }
            } else {
                selectedSet.add(candidate);
            }

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
