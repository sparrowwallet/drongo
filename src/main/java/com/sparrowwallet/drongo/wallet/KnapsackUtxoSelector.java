package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Transaction;

import java.util.*;
import java.util.stream.Collectors;

public class KnapsackUtxoSelector extends SingleSetUtxoSelector {
    private static final long MIN_CHANGE = Transaction.SATOSHIS_PER_BITCOIN / 1000;

    private final long noInputsFee;

    public KnapsackUtxoSelector(long noInputsFee) {
        this.noInputsFee = noInputsFee;
    }

    @Override
    public Collection<BlockTransactionHashIndex> select(long targetValue, Collection<OutputGroup> candidates) {
        long actualTargetValue = targetValue + noInputsFee;

        List<OutputGroup> shuffled = new ArrayList<>(candidates);
        Collections.shuffle(shuffled);

        OutputGroup lowestLarger = null;
        List<OutputGroup> applicableGroups = new ArrayList<>();
        long totalLower = 0;

        for(OutputGroup outputGroup : shuffled) {
            if(outputGroup.getEffectiveValue() == actualTargetValue) {
                return new ArrayList<>(outputGroup.getUtxos());
            } else if(outputGroup.getEffectiveValue() < actualTargetValue + MIN_CHANGE) {
                applicableGroups.add(outputGroup);
                totalLower += outputGroup.getEffectiveValue();
            } else if(lowestLarger == null || outputGroup.getEffectiveValue() < lowestLarger.getEffectiveValue()) {
                lowestLarger = outputGroup;
            }
        }

        if(totalLower == actualTargetValue) {
            return applicableGroups.stream().flatMap(outputGroup -> outputGroup.getUtxos().stream()).collect(Collectors.toList());
        }

        if(totalLower < actualTargetValue) {
            if(lowestLarger == null) {
                return Collections.emptyList();
            }
            return lowestLarger.getUtxos();
        }

        //We now have a list of UTXOs that are all smaller than the target + MIN_CHANGE, but together sum to greater than actualTargetValue
        // Solve subset sum by stochastic approximation

        applicableGroups.sort((a, b) -> Long.compare(b.getEffectiveValue(), a.getEffectiveValue()));
        boolean[] bestSelection = new boolean[applicableGroups.size()];

        long bestValue = findApproximateBestSubset(applicableGroups, totalLower, actualTargetValue, bestSelection);
        if(bestValue != actualTargetValue && totalLower >= actualTargetValue + MIN_CHANGE) {
            bestValue = findApproximateBestSubset(applicableGroups, totalLower, actualTargetValue + MIN_CHANGE, bestSelection);
        }

        // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
        //                                   or the next bigger coin is closer), return the bigger coin

        if(lowestLarger != null && ((bestValue != actualTargetValue && bestValue < actualTargetValue + MIN_CHANGE) || lowestLarger.getEffectiveValue() <= bestValue)) {
            return lowestLarger.getUtxos();
        } else {
            List<BlockTransactionHashIndex> utxos = new ArrayList<>();
            for(int i = 0; i < applicableGroups.size(); i++) {
                if(bestSelection[i]) {
                    utxos.addAll(applicableGroups.get(i).getUtxos());
                }
            }
            return utxos;
        }
    }

    private long findApproximateBestSubset(List<OutputGroup> groups, long totalLower, long actualTargetValue, boolean[] bestSelection) {
        int iterations = 1000;

        boolean[] includedSelection;

        Arrays.fill(bestSelection, true);
        long bestValue = totalLower;

        Random random = new Random();

        for(int rep = 0; rep < iterations && bestValue != actualTargetValue; rep++) {
            includedSelection = new boolean[groups.size()];
            Arrays.fill(includedSelection, false);
            long total = 0;
            boolean reachedTarget = false;

            for(int pass = 0; pass < 2 && !reachedTarget; pass++) {
                for(int i = 0; i < groups.size(); i++) {
                    //The solver here uses a randomized algorithm,
                    //the randomness serves no real security purpose but is just
                    //needed to prevent degenerate behavior and it is important
                    //that the rng is fast. We do not use a constant random sequence,
                    //because there may be some privacy improvement by making
                    //the selection random.

                    if(pass == 0 ? random.nextBoolean() : !includedSelection[i]) {
                        total += groups.get(i).getEffectiveValue();
                        includedSelection[i] = true;
                        if(total >= actualTargetValue) {
                            reachedTarget = true;
                            if(total < bestValue) {
                                bestValue = total;
                                System.arraycopy(includedSelection, 0, bestSelection, 0, groups.size());
                            }
                            total -= groups.get(i).getEffectiveValue();
                            includedSelection[i] = false;
                        }
                    }
                }
            }
        }

        return bestValue;
    }
}
