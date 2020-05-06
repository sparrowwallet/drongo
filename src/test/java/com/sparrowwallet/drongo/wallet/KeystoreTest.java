package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;
import org.junit.Assert;
import org.junit.Test;

public class KeystoreTest {
    @Test
    public void testExtendedPrivateKey() {
        Keystore keystore = new Keystore();
        keystore.setSeed(Utils.hexToBytes("727ecfcf0bce9d8ec0ef066f7aeb845c271bdd4ee06a37398cebd40dc810140bb620b6c10a8ad671afdceaf37aa55d92d6478f747e8b92430dd938ab5be961dd"));

        Assert.assertEquals("xprv9s21ZrQH143K3rN5vhm4bKDKsk1PmUK1mzxSMwkVSp2GbomwGmjLaGqrs8Nn9r14jCsfCNWfTR6pAtCsJutUH6QSHX65CePNW3YVyGxqvJa", keystore.getExtendedPrivateKey().toString());
    }

    @Test
    public void testExtendedPrivateKeyTwo() {
        Keystore keystore = new Keystore();
        keystore.setSeed(Utils.hexToBytes("4d8c47d0d6241169d0b17994219211c4a980f7146bb70dbc897416790e9de23a6265c708b88176e24f6eb7378a7c55cd4bdc067cafe574eaf3480f9a41c3c43c"));

        Assert.assertEquals("xprv9s21ZrQH143K4AkrxAyivDeTCWhZV6fdLfBRR8QerWe9hHiRqMjBMj9MFNef7oFufgcDcW54LhguPNm6MVLEMWPX5qxKhmNjCzi9Zy6yhkc", keystore.getExtendedPrivateKey().toString());
    }
}
