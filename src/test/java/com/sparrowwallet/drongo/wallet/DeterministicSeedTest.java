package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.crypto.KeyDeriver;
import org.junit.Assert;
import org.junit.Test;

public class DeterministicSeedTest {
    @Test
    public void testEncryption() {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";

        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);
        KeyDeriver keyDeriver = seed.getEncryptionType().getDeriver().getKeyDeriver();
        DeterministicSeed encryptedSeed = seed.encrypt(keyDeriver.deriveKey("pass"));

        DeterministicSeed decryptedSeed = encryptedSeed.decrypt("pass");
        Assert.assertEquals(words, decryptedSeed.getMnemonicString());
    }
}
