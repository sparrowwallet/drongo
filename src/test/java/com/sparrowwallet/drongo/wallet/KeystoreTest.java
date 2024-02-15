package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class KeystoreTest {
    @Test
    public void testExtendedPrivateKey() throws MnemonicException {
        Keystore keystore = new Keystore();
        DeterministicSeed seed = new DeterministicSeed("absent essay fox snake vast pumpkin height crouch silent bulb excuse razor", "", 0, DeterministicSeed.Type.BIP39);
        keystore.setSeed(seed);

        Assertions.assertEquals("xprv9s21ZrQH143K3rN5vhm4bKDKsk1PmUK1mzxSMwkVSp2GbomwGmjLaGqrs8Nn9r14jCsfCNWfTR6pAtCsJutUH6QSHX65CePNW3YVyGxqvJa", keystore.getExtendedMasterPrivateKey().toString());
    }

    @Test
    public void testFromSeed() throws MnemonicException {
        ScriptType p2pkh = ScriptType.P2PKH;
        DeterministicSeed seed = new DeterministicSeed("absent essay fox snake vast pumpkin height crouch silent bulb excuse razor", "", 0, DeterministicSeed.Type.BIP39);
        Keystore keystore = Keystore.fromSeed(seed, p2pkh.getDefaultDerivation());

        Assertions.assertEquals("xpub6D9jqMkBdgTqrzTxXVo2w8yZCa7HvzJTybFevJ2StHSxBRhs8dzsVEke9TQ9QjZCKbWZvzbc8iSScBbsCiA11wT28hZmCv3YmjSFEqCLmMn", keystore.getExtendedPublicKey().toString());
    }
}
