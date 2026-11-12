package com.sparrowwallet.drongo.wallet;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Locale;

public class SeedQRTest {
    @Test
    public void testStandardSeedQRIgnoresDefaultLocale() {
        DeterministicSeed seed = new DeterministicSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", 0, DeterministicSeed.Type.BIP39);

        Locale defaultLocale = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("fa-IR"));
            String seedQr = SeedQR.getSeedQR(seed);
            Assertions.assertEquals("0000".repeat(11) + "0003", seedQr);
            Assertions.assertEquals(seed.getMnemonicCode(), SeedQR.getSeed(seedQr).getMnemonicCode());
        } finally {
            Locale.setDefault(defaultLocale);
        }
    }
}
