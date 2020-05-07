package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.ScriptType;
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

    @Test
    public void testFromSeed() {
        ScriptType p2pkh = ScriptType.P2PKH;
        Keystore keystore = Keystore.fromSeed(Utils.hexToBytes("4d8c47d0d6241169d0b17994219211c4a980f7146bb70dbc897416790e9de23a6265c708b88176e24f6eb7378a7c55cd4bdc067cafe574eaf3480f9a41c3c43c"), p2pkh.getDefaultDerivation());

        Assert.assertEquals("xpub6DCH2YkjweBu5zQheCWgSu6o26AENhApkS2taXaJBsi6vthRytPTaY2Sh4zDHj7oCVhYxx5974HbSbKxh26ah7N6VVw1U8kS2H5HfPUXecq", keystore.getExtendedPublicKey().toString());
    }
}
