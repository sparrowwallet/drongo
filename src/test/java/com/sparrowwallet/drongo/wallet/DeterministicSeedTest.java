package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.crypto.KeyDeriver;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class DeterministicSeedTest {
    @Test
    public void testEncryption() {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";

        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);
        KeyDeriver keyDeriver = seed.getEncryptionType().getDeriver().getKeyDeriver();
        DeterministicSeed encryptedSeed = seed.encrypt(keyDeriver.deriveKey("pass"));

        DeterministicSeed decryptedSeed = encryptedSeed.decrypt("pass");
        Assertions.assertEquals(words, decryptedSeed.getMnemonicString().asString());
    }

    @Test
    public void testBip39Vector1() throws MnemonicException {
        String words = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always";

        DeterministicSeed seed = new DeterministicSeed(words, "TREZOR", 0, DeterministicSeed.Type.BIP39);
        Keystore keystore = Keystore.fromSeed(seed, KeyDerivation.parsePath("m/0'"));
        Assertions.assertEquals("xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae", keystore.getExtendedMasterPrivateKey().toString());
    }

    @Test
    public void testBip39Vector2() throws MnemonicException {
        String words = "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside";

        DeterministicSeed seed = new DeterministicSeed(words, "TREZOR", 0, DeterministicSeed.Type.BIP39);
        Keystore keystore = Keystore.fromSeed(seed, KeyDerivation.parsePath("m/0'"));
        Assertions.assertEquals("xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems", keystore.getExtendedMasterPrivateKey().toString());
    }
}
