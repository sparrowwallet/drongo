package com.sparrowwallet.drongo.wallet;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class WalletModelTest {
    @Test
    public void testUkeyCore26() {
        Assertions.assertEquals("ukey", WalletModel.UKEY_CORE_26.getType());
        Assertions.assertEquals("UKey Core 26", WalletModel.UKEY_CORE_26.toDisplayString());
        Assertions.assertEquals(WalletModel.UKEY_CORE_26, WalletModel.fromType("ukey"));
        Assertions.assertTrue(WalletModel.UKEY_CORE_26.hasUsb());
        Assertions.assertFalse(WalletModel.UKEY_CORE_26.requiresPinPrompt());
        Assertions.assertFalse(WalletModel.UKEY_CORE_26.externalPassphraseEntry());
        Assertions.assertFalse(WalletModel.UKEY_CORE_26.hasZeroInPin());
    }
}
