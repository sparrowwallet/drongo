package com.sparrowwallet.drongo.wallet;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

public class PriorityUtxoSelector extends SingleSetUtxoSelector {
    private final int currentBlockHeight;

    public PriorityUtxoSelector(int currentBlockHeight) {
        this.currentBlockHeight = currentBlockHeight;
    }

    @Override
    public Collection<BlockTransactionHashIndex> select(long targetValue, Collection<OutputGroup> candidates) {
        List<BlockTransactionHashIndex> selected = new ArrayList<>();

        List<BlockTransactionHashIndex> sorted = candidates.stream().flatMap(outputGroup -> outputGroup.getUtxos().stream()).filter(ref -> ref.getHeight() > 0).collect(Collectors.toList());
        sort(sorted);

        //Testing only: remove
        Collections.reverse(sorted);

        long total = 0;
        for(BlockTransactionHashIndex reference : sorted) {
            if(total > targetValue) {
                break;
            }

            selected.add(reference);
            total += reference.getValue();
        }

        return selected;
    }

    private void sort(List<BlockTransactionHashIndex> outputs) {
        outputs.sort((a, b) -> {
            int depthA = currentBlockHeight - a.getHeight();
            int depthB = currentBlockHeight - b.getHeight();

            Long valueA = a.getValue();
            Long valueB = b.getValue();

            BigInteger coinDepthA = BigInteger.valueOf(depthA).multiply(BigInteger.valueOf(valueA));
            BigInteger coinDepthB = BigInteger.valueOf(depthB).multiply(BigInteger.valueOf(valueB));

            int coinDepthCompare = coinDepthB.compareTo(coinDepthA);
            if (coinDepthCompare != 0) {
                return coinDepthCompare;
            }

            // The "coin*days" destroyed are equal, sort by value alone to get the lowest transaction size.
            int coinValueCompare = valueB.compareTo(valueA);
            if (coinValueCompare != 0) {
                return coinValueCompare;
            }

            return a.compareTo(b);
        });
    }
}
