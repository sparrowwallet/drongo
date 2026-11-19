package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class UtxoSelectorTest {
    private static final double FEE_RATE = 10.0;
    private static final long INPUT_WEIGHT_UNITS = 272;

    private static int index = 0;

    private static OutputGroup group(long value) {
        OutputGroup outputGroup = new OutputGroup(ScriptType.P2WPKH, 1000, INPUT_WEIGHT_UNITS, FEE_RATE, FEE_RATE);
        outputGroup.add(new BlockTransactionHashIndex(Sha256Hash.ZERO_HASH, 900, null, null, index++, value), true, false);
        return outputGroup;
    }

    //Two coins worth 10,240 sats after fees at 10 sat/vB, with three dust coins whose effective values sum to -1,140
    private static List<OutputGroup> poolWithDust() {
        List<OutputGroup> pool = new ArrayList<>(List.of(group(5800), group(5800)));
        for(int i = 0; i < 3; i++) {
            OutputGroup dust = group(300);
            Assertions.assertTrue(dust.getEffectiveValue() < 0);
            pool.add(dust);
        }

        return pool;
    }

    private static void assertSelectsOnlyTheCoins(Collection<BlockTransactionHashIndex> selected) {
        Assertions.assertEquals(2, selected.size());
        Assertions.assertTrue(selected.stream().allMatch(utxo -> utxo.getValue() == 5800));
    }

    @Test
    public void knapsackIgnoresDust() {
        for(int i = 0; i < 20; i++) {
            assertSelectsOnlyTheCoins(new KnapsackUtxoSelector(0).select(10000, poolWithDust()));
        }
    }

    @Test
    public void branchAndBoundIgnoresDust() {
        assertSelectsOnlyTheCoins(new BnBUtxoSelector(0, 1000).select(10000, poolWithDust()));
    }
}
