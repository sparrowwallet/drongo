package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public class BlockTransactionHashTest {
    @Test
    public void confirmations() {
        Assertions.assertEquals(0, new BlockTransaction(Sha256Hash.ZERO_HASH, 0, null, null, null).getConfirmations(216));
        Assertions.assertEquals(0, new BlockTransaction(Sha256Hash.ZERO_HASH, -1, null, null, null).getConfirmations(216));
        Assertions.assertEquals(1, new BlockTransaction(Sha256Hash.ZERO_HASH, 211, null, null, null).getConfirmations(211));
        Assertions.assertEquals(6, new BlockTransaction(Sha256Hash.ZERO_HASH, 211, null, null, null).getConfirmations(216));
    }

    @Test
    public void confirmationsBelowTip() {
        Assertions.assertEquals(0, new BlockTransaction(Sha256Hash.ZERO_HASH, 211, null, null, null).getConfirmations(210));
        Assertions.assertEquals(0, new BlockTransaction(Sha256Hash.ZERO_HASH, 211, null, null, null).getConfirmations(203));
    }

    @Test
    public void heightOrder() {
        Set<BlockTransactionHash> references = new TreeSet<>();
        for(int height : new int[] {-1, -5, 211, 0, -2, 210}) {
            references.add(new BlockTransaction(Sha256Hash.ZERO_HASH, height, null, null, null));
        }

        Assertions.assertEquals(List.of(210, 211, 0, -1, -2, -5), references.stream().map(BlockTransactionHash::getHeight).toList());
    }

    @Test
    public void heightOrderIsTotal() {
        int[] heights = new int[] {963657, -1000000000, -6, -8, -4, -7, -1000000001, -5, -963659, 0, -1, Integer.MAX_VALUE, Integer.MAX_VALUE - 1, Integer.MIN_VALUE};
        Set<BlockTransactionHash> sorted = new TreeSet<>();
        for(int height : heights) {
            sorted.add(new BlockTransaction(Sha256Hash.ZERO_HASH, height, null, null, null));
        }
        Assertions.assertEquals(heights.length, sorted.size());

        Set<BlockTransactionHash> references = new TreeSet<>(sorted.stream().toList());
        for(int height : heights) {
            Assertions.assertTrue(references.remove(new BlockTransaction(Sha256Hash.ZERO_HASH, height, null, null, null)), "height " + height);
        }
        Assertions.assertTrue(references.isEmpty());

        for(int a : heights) {
            BlockTransactionHash first = new BlockTransaction(Sha256Hash.ZERO_HASH, a, null, null, null);
            for(int b : heights) {
                BlockTransactionHash second = new BlockTransaction(Sha256Hash.ZERO_HASH, b, null, null, null);
                Assertions.assertEquals(Integer.signum(first.compareTo(second)), -Integer.signum(second.compareTo(first)), a + " " + b);
                for(int c : heights) {
                    BlockTransactionHash third = new BlockTransaction(Sha256Hash.ZERO_HASH, c, null, null, null);
                    if(first.compareTo(second) < 0 && second.compareTo(third) < 0) {
                        Assertions.assertTrue(first.compareTo(third) < 0, a + " " + b + " " + c);
                    }
                }
            }
        }
    }
}
