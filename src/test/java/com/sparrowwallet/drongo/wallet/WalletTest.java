package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.crypto.Argon2KeyDeriver;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.crypto.KeyDeriver;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.Assert;
import org.junit.Test;

public class WalletTest {
    @Test
    public void encryptTest() throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE);
        wallet.setScriptType(ScriptType.P2PKH);
        Keystore keystore = Keystore.fromSeed(seed, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2PKH, wallet.getKeystores(), 1));

        KeyDeriver keyDeriver = new Argon2KeyDeriver();
        Key key = keyDeriver.deriveKey("pass");
        wallet.encrypt(key);

        wallet.decrypt("pass");
    }

    @Test
    public void makeLabelsUnique() {
        Wallet wallet = new Wallet();
        Keystore keystore1 = new Keystore("BIP39");
        wallet.getKeystores().add(keystore1);

        Keystore keystore2 = new Keystore("BIP39 2");
        wallet.getKeystores().add(keystore2);

        Keystore keystore3 = new Keystore("Coldcard");
        wallet.getKeystores().add(keystore3);

        Keystore keystore4 = new Keystore("Coldcard2");
        wallet.getKeystores().add(keystore4);

        Keystore keystore5 = new Keystore("Coldcard -1");
        wallet.getKeystores().add(keystore5);

        Keystore keystore = new Keystore("BIP39");
        wallet.makeLabelsUnique(keystore);
        Assert.assertEquals("BIP39 3", keystore1.getLabel());
        Assert.assertEquals("BIP39 4", keystore.getLabel());

        Keystore cckeystore = new Keystore("Coldcard");
        wallet.makeLabelsUnique(cckeystore);
        Assert.assertEquals("Coldcard 3", keystore3.getLabel());
        Assert.assertEquals("Coldcard 4", cckeystore.getLabel());

        Keystore eekeystore = new Keystore("Electrum");
        wallet.makeLabelsUnique(cckeystore);
        Assert.assertEquals("Electrum", eekeystore.getLabel());
        wallet.getKeystores().add(eekeystore);

        Keystore eekeystore2 = new Keystore("Electrum");
        wallet.makeLabelsUnique(eekeystore2);
        Assert.assertEquals("Electrum 1", eekeystore.getLabel());
        Assert.assertEquals("Electrum 2", eekeystore2.getLabel());

        Keystore defaultKeystore = new Keystore();
        wallet.getKeystores().add(defaultKeystore);
        Keystore defaultKeystore2 = new Keystore();
        wallet.makeLabelsUnique(defaultKeystore2);
        Assert.assertEquals("Keystore 2", defaultKeystore2.getLabel());
        wallet.getKeystores().add(defaultKeystore2);
        Keystore defaultKeystore3 = new Keystore();
        wallet.makeLabelsUnique(defaultKeystore3);
        Assert.assertEquals("Keystore 3", defaultKeystore3.getLabel());
        wallet.getKeystores().add(defaultKeystore3);
        Keystore defaultKeystore4 = new Keystore("Keystore");
        wallet.makeLabelsUnique(defaultKeystore4);
        Assert.assertEquals("Keystore 4", defaultKeystore4.getLabel());
        wallet.getKeystores().add(defaultKeystore4);
        Keystore defaultKeystore5 = new Keystore("Keystore 4");
        wallet.makeLabelsUnique(defaultKeystore5);
        Assert.assertEquals("Keystore 4 2", defaultKeystore5.getLabel());
        wallet.getKeystores().add(defaultKeystore5);
    }

    @Test
    public void p2pkhDerivationTest() throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE);
        wallet.setScriptType(ScriptType.P2PKH);
        Keystore keystore = Keystore.fromSeed(seed, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2PKH, wallet.getKeystores(), 1));

        Assert.assertEquals("12kTQjuWDp7Uu6PwY6CsS1KLTt3d1DBHZa", wallet.getAddress(KeyPurpose.RECEIVE, 0).toString());
        Assert.assertEquals("1HbQwQCitHQxVtP39isXmUdHx7hQCZovrK", wallet.getAddress(KeyPurpose.RECEIVE, 1).toString());
    }

    @Test
    public void p2shP2wpkhDerivationTest() throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE);
        wallet.setScriptType(ScriptType.P2SH_P2WPKH);
        Keystore keystore = Keystore.fromSeed(seed, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2SH_P2WPKH, wallet.getKeystores(), 1));

        Assert.assertEquals("3NZLE4TntsjtcZ5MbrfxwtYo9meBVybVQj", wallet.getAddress(KeyPurpose.RECEIVE, 0).toString());
        Assert.assertEquals("32YBBuRsp8XTeLx4T6BmD2L4nANGaNDkSg", wallet.getAddress(KeyPurpose.RECEIVE, 1).toString());
    }

    @Test
    public void p2wpkhDerivationTest() throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE);
        wallet.setScriptType(ScriptType.P2WPKH);
        Keystore keystore = Keystore.fromSeed(seed, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, wallet.getKeystores(), 1));

        Assert.assertEquals("bc1quvxdut936uswuxwxrk6nvjmgwxh463r0fjwn55", wallet.getAddress(KeyPurpose.RECEIVE, 0).toString());
        Assert.assertEquals("bc1q95j2862dz7mqpraw6qdjc70gumyu5z7adgq9x9", wallet.getAddress(KeyPurpose.RECEIVE, 1).toString());
    }

    @Test
    public void p2shDerivationTest() throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);

        String words2 = "chef huge whisper year move obscure post pepper play minute foster lawn";
        DeterministicSeed seed2 = new DeterministicSeed(words2, "", 0, DeterministicSeed.Type.BIP39);

        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.MULTI);
        wallet.setScriptType(ScriptType.P2SH);
        Keystore keystore = Keystore.fromSeed(seed, ScriptType.P2PKH.getDefaultDerivation());
        Assert.assertEquals("xprv9s21ZrQH143K4G3jeUxf7h93qLeinXNULjjaef1yZFXpoc5D16iHEFkgJ7ThkWzAEBwNNwyJFtrVhJVJRjCc9ew76JrgsVoXT4VYHJBbbSV", keystore.getExtendedMasterPrivateKey().toString());
        Assert.assertEquals("xpub6DLZWwJhGmq2SwdAytDWhCUrM4MojYSLHhHMZ1sob9UGXnSvgczEL7zV1wtcy9qcH6yduKMp1bPWcSxxSmz6LEpw4xTABLL3XwX5KGzkNqZ", keystore.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore);
        Keystore keystore2 = Keystore.fromSeed(seed2, ScriptType.P2PKH.getDefaultDerivation());
        Assert.assertEquals("xprv9s21ZrQH143K4FNcBwXNXfzVNskpoRS7cf4jQTLrhbPkhhXp8hz4QRXT62HziiHziM3Pxyd2Qx3UQkoRpcDu2BauuJJRdyrduXBJGgjAgFx", keystore2.getExtendedMasterPrivateKey().toString());
        Assert.assertEquals("xpub6ChqMsFBYpJiJYzcJgEvddHtbZr1mTaE1o4RbhFRBAYVxN8SScGb9kjwkXtM33JKejR16gBZhNbkV14AccetR5u2McnCgTCpDBfa8hee9v8", keystore2.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore2);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI, ScriptType.P2SH, wallet.getKeystores(), 2));

        Assert.assertEquals("38kq6yz4VcYymTExQPY3gppbz38mtPLveK", wallet.getAddress(KeyPurpose.RECEIVE, 0).toString());
        Assert.assertEquals("3EdKaNsnjBTBggWcSMRyVju6GbHWy68mAH", wallet.getAddress(KeyPurpose.CHANGE, 1).toString());
    }

    @Test
    public void p2shP2wshDerivationTest() throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);

        String words2 = "chef huge whisper year move obscure post pepper play minute foster lawn";
        DeterministicSeed seed2 = new DeterministicSeed(words2, "", 0, DeterministicSeed.Type.BIP39);

        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.MULTI);
        wallet.setScriptType(ScriptType.P2SH_P2WSH);
        Keystore keystore = Keystore.fromSeed(seed, ScriptType.P2PKH.getDefaultDerivation());
        Assert.assertEquals("xprv9s21ZrQH143K4G3jeUxf7h93qLeinXNULjjaef1yZFXpoc5D16iHEFkgJ7ThkWzAEBwNNwyJFtrVhJVJRjCc9ew76JrgsVoXT4VYHJBbbSV", keystore.getExtendedMasterPrivateKey().toString());
        Assert.assertEquals("xpub6DLZWwJhGmq2SwdAytDWhCUrM4MojYSLHhHMZ1sob9UGXnSvgczEL7zV1wtcy9qcH6yduKMp1bPWcSxxSmz6LEpw4xTABLL3XwX5KGzkNqZ", keystore.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore);
        Keystore keystore2 = Keystore.fromSeed(seed2, ScriptType.P2PKH.getDefaultDerivation());
        Assert.assertEquals("xprv9s21ZrQH143K4FNcBwXNXfzVNskpoRS7cf4jQTLrhbPkhhXp8hz4QRXT62HziiHziM3Pxyd2Qx3UQkoRpcDu2BauuJJRdyrduXBJGgjAgFx", keystore2.getExtendedMasterPrivateKey().toString());
        Assert.assertEquals("xpub6ChqMsFBYpJiJYzcJgEvddHtbZr1mTaE1o4RbhFRBAYVxN8SScGb9kjwkXtM33JKejR16gBZhNbkV14AccetR5u2McnCgTCpDBfa8hee9v8", keystore2.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore2);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI, ScriptType.P2SH_P2WSH, wallet.getKeystores(), 2));

        Assert.assertEquals("3Mw8xqAHh8g3eBvh7q1UEUmoexqdXDK9Tf", wallet.getAddress(KeyPurpose.RECEIVE, 0).toString());
        Assert.assertEquals("35dFo1ivJ8jyHpyf42MWvnYf5LBU8Siren", wallet.getAddress(KeyPurpose.CHANGE, 1).toString());
    }

    @Test
    public void p2wshDerivationTest() throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);

        String words2 = "chef huge whisper year move obscure post pepper play minute foster lawn";
        DeterministicSeed seed2 = new DeterministicSeed(words2, "", 0, DeterministicSeed.Type.BIP39);

        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.MULTI);
        wallet.setScriptType(ScriptType.P2WSH);
        Keystore keystore = Keystore.fromSeed(seed, ScriptType.P2PKH.getDefaultDerivation());
        Assert.assertEquals("xprv9s21ZrQH143K4G3jeUxf7h93qLeinXNULjjaef1yZFXpoc5D16iHEFkgJ7ThkWzAEBwNNwyJFtrVhJVJRjCc9ew76JrgsVoXT4VYHJBbbSV", keystore.getExtendedMasterPrivateKey().toString());
        Assert.assertEquals("xpub6DLZWwJhGmq2SwdAytDWhCUrM4MojYSLHhHMZ1sob9UGXnSvgczEL7zV1wtcy9qcH6yduKMp1bPWcSxxSmz6LEpw4xTABLL3XwX5KGzkNqZ", keystore.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore);
        Keystore keystore2 = Keystore.fromSeed(seed2, ScriptType.P2PKH.getDefaultDerivation());
        Assert.assertEquals("xprv9s21ZrQH143K4FNcBwXNXfzVNskpoRS7cf4jQTLrhbPkhhXp8hz4QRXT62HziiHziM3Pxyd2Qx3UQkoRpcDu2BauuJJRdyrduXBJGgjAgFx", keystore2.getExtendedMasterPrivateKey().toString());
        Assert.assertEquals("xpub6ChqMsFBYpJiJYzcJgEvddHtbZr1mTaE1o4RbhFRBAYVxN8SScGb9kjwkXtM33JKejR16gBZhNbkV14AccetR5u2McnCgTCpDBfa8hee9v8", keystore2.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore2);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI, ScriptType.P2WSH, wallet.getKeystores(), 2));

        Assert.assertEquals("bc1q20e4vm656h5lvmngz9ztz6hjzftvh39yzngqhuqzk8qzj7tqnzaqgclrwc", wallet.getAddress(KeyPurpose.RECEIVE, 0).toString());
        Assert.assertEquals("bc1q2epdx7dplwaas2jucfrzmxm8350rqh68hs6vqreysku80ye44mfqla85f2", wallet.getAddress(KeyPurpose.CHANGE, 1).toString());
    }
}
