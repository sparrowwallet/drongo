package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Transaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class BnBUtxoSelector extends SingleSetUtxoSelector {
    private static final Logger log = LoggerFactory.getLogger(BnBUtxoSelector.class);

    private static final int TOTAL_TRIES = 100000;

    private final long noInputsFee;
    private final long costOfChangeValue;

    public BnBUtxoSelector(long noInputsFee, long costOfChangeValue) {
        this.noInputsFee = noInputsFee;
        this.costOfChangeValue = costOfChangeValue;
    }

    @Override
    public Collection<BlockTransactionHashIndex> select(long targetValue, Collection<OutputGroup> candidates) {
        List<OutputGroup> utxoPool = new ArrayList<>(candidates);

        long currentValue = 0;

        ArrayDeque<Boolean> currentSelection = new ArrayDeque<>(utxoPool.size());
        long actualTargetValue = targetValue + noInputsFee;
        log.debug("Selected must be: " + actualTargetValue + " < x < " + (actualTargetValue + costOfChangeValue));

        long currentAvailableValue = utxoPool.stream().mapToLong(OutputGroup::getEffectiveValue).sum();
        if(currentAvailableValue < targetValue) {
            return Collections.emptyList();
        }

        utxoPool.sort((a, b) -> Long.compare(b.getEffectiveValue(), a.getEffectiveValue()));

        long currentWasteValue = 0;
        ArrayDeque<Boolean> bestSelection = null;
        long bestWasteValue = Transaction.MAX_BITCOIN;

        // Depth First search loop for choosing the UTXOs
        for(int i = 0; i < TOTAL_TRIES; i++) {
            boolean backtrack = false;
            if(currentValue + currentAvailableValue < actualTargetValue ||  // Cannot possibly reach target with the amount remaining in the currentAvailableValue
                currentValue > actualTargetValue + costOfChangeValue ||     //  Selected value is out of range, go back and try other branch
                (currentWasteValue > bestWasteValue && !utxoPool.isEmpty() && (utxoPool.get(0).getFee() - utxoPool.get(0).getLongTermFee() > 0))) {
                backtrack = true;
            } else if(currentValue >= actualTargetValue) {                  // Selected value is within range
                currentWasteValue += (currentValue - actualTargetValue);    // This is the excess value which is added to the waste for the below comparison
                // Adding another UTXO after this check could bring the waste down if the long term fee is higher than the current fee.
                // However we are not going to explore that because this optimization for the waste is only done when we have hit our target
                // value. Adding any more UTXOs will be just burning the UTXO; it will go entirely to fees. Thus we aren't going to
                // explore any more UTXOs to avoid burning money like that.
                if(currentWasteValue <= bestWasteValue) {
                    bestSelection = currentSelection;
                    bestSelection = resize(bestSelection, utxoPool.size());
                    bestWasteValue = currentWasteValue;
                }
                currentWasteValue -= (currentValue - actualTargetValue);    // Remove the excess value as we will be selecting different coins now
                backtrack = true;
            }

            if(backtrack) {
                // Walk backwards to find the last included UTXO that still needs to have its omission branch traversed
                while(!currentSelection.isEmpty() && !currentSelection.getLast()) {
                    currentSelection.removeLast();
                    currentAvailableValue += utxoPool.get(currentSelection.size()).getEffectiveValue();
                }

                if(currentSelection.isEmpty()) {                            // We have walked back to the first utxo and no branch is untraversed. All solutions searched
                    break;
                }

                // Output was included on previous iterations, try excluding now
                currentSelection.removeLast();
                currentSelection.add(Boolean.FALSE);

                OutputGroup utxo = utxoPool.get(currentSelection.size() - 1);
                currentValue -= utxo.getEffectiveValue();
                currentWasteValue -= (utxo.getFee() - utxo.getLongTermFee());
            } else {                                                        // Moving forwards, continuing down this branch
                OutputGroup utxo = utxoPool.get(currentSelection.size());

                // Remove this utxo from the currentAvailableValue utxo amount
                currentAvailableValue -= utxo.getEffectiveValue();

                // Avoid searching a branch if the previous UTXO has the same value and same waste and was excluded. Since the ratio of fee to
                // long term fee is the same, we only need to check if one of those values match in order to know that the waste is the same.
                if(!currentSelection.isEmpty() && !currentSelection.getLast() &&
                    utxo.getEffectiveValue() == utxoPool.get(currentSelection.size() - 1).getEffectiveValue() &&
                    utxo.getFee() == utxoPool.get(currentSelection.size() - 1).getFee()) {
                    currentSelection.add(Boolean.FALSE);
                } else {
                    // Inclusion branch first (Largest First Exploration)
                    currentSelection.add(Boolean.TRUE);
                    currentValue += utxo.getEffectiveValue();
                    currentWasteValue += (utxo.getFee() - utxo.getLongTermFee());
                    printCurrentUtxoSet(utxoPool, currentSelection, currentValue);
                }
            }
        }

        // Check for solution
        if(bestSelection == null || bestSelection.isEmpty()) {
            log.debug("No result found");
            return Collections.emptyList();
        }

        // Create output list of UTXOs
        List<BlockTransactionHashIndex> outList = new ArrayList<>();
        int i = 0;
        for(Iterator<Boolean> iter = bestSelection.iterator(); iter.hasNext(); i++) {
            if(iter.next()) {
                outList.addAll(utxoPool.get(i).getUtxos());
            }
        }

        return outList;
    }

    private ArrayDeque<Boolean> resize(ArrayDeque<Boolean> deque, int size) {
        Boolean[] arr = new Boolean[size];
        Arrays.fill(arr, Boolean.FALSE);

        Boolean[] dequeArr = deque.toArray(new Boolean[deque.size()]);
        System.arraycopy(dequeArr, 0, arr, 0, Math.min(arr.length, dequeArr.length));

        return new ArrayDeque<>(Arrays.asList(arr));
    }

    private void printCurrentUtxoSet(List<OutputGroup> utxoPool, ArrayDeque<Boolean> currentSelection, long currentValue) {
        long inputsFee = 0;
        StringJoiner joiner = new StringJoiner(" + ");
        int i = 0;
        for(Iterator<Boolean> iter = currentSelection.iterator(); iter.hasNext(); i++) {
            if(iter.next()) {
                joiner.add(Long.toString(utxoPool.get(i).getEffectiveValue()));
                inputsFee += utxoPool.get(i).getFee();
            }
        }
        long noChangeFeeRequiredAmt = noInputsFee + inputsFee;
        log.debug(joiner.toString() + " = " + currentValue + " (plus fee of " + noChangeFeeRequiredAmt + ")");
    }
}
