package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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
}
