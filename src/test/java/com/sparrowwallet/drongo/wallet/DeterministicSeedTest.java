package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.crypto.KeyCrypter;
import com.sparrowwallet.drongo.crypto.ScryptKeyCrypter;
import org.junit.Assert;
import org.junit.Test;

public class DeterministicSeedTest {
    @Test
    public void testEncryption() {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";

        KeyCrypter keyCrypter = new ScryptKeyCrypter();
        Key key = keyCrypter.deriveKey("pass");
        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);
        DeterministicSeed encryptedSeed = seed.encrypt(keyCrypter, key);

        System.out.println(Utils.bytesToHex(encryptedSeed.getEncryptedData().getInitialisationVector()));
        System.out.println(Utils.bytesToHex(encryptedSeed.getEncryptedData().getEncryptedBytes()));

        KeyCrypter keyCrypter2 = new ScryptKeyCrypter();
        Key key2 = keyCrypter2.deriveKey("pass");
        seed = encryptedSeed.decrypt(keyCrypter2, key2);
        Assert.assertEquals(words, seed.getMnemonicString());
    }
}
