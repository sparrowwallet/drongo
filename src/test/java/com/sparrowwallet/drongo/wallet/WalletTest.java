package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.Argon2KeyDeriver;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.crypto.KeyDeriver;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

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
        Assertions.assertEquals("BIP39 3", keystore1.getLabel());
        Assertions.assertEquals("BIP39 4", keystore.getLabel());

        Keystore cckeystore = new Keystore("Coldcard");
        wallet.makeLabelsUnique(cckeystore);
        Assertions.assertEquals("Coldcard 3", keystore3.getLabel());
        Assertions.assertEquals("Coldcard 4", cckeystore.getLabel());

        Keystore eekeystore = new Keystore("Electrum");
        wallet.makeLabelsUnique(cckeystore);
        Assertions.assertEquals("Electrum", eekeystore.getLabel());
        wallet.getKeystores().add(eekeystore);

        Keystore eekeystore2 = new Keystore("Electrum");
        wallet.makeLabelsUnique(eekeystore2);
        Assertions.assertEquals("Electrum 1", eekeystore.getLabel());
        Assertions.assertEquals("Electrum 2", eekeystore2.getLabel());

        Keystore defaultKeystore = new Keystore();
        wallet.getKeystores().add(defaultKeystore);
        Keystore defaultKeystore2 = new Keystore();
        wallet.makeLabelsUnique(defaultKeystore2);
        Assertions.assertEquals("Keystore 2", defaultKeystore2.getLabel());
        wallet.getKeystores().add(defaultKeystore2);
        Keystore defaultKeystore3 = new Keystore();
        wallet.makeLabelsUnique(defaultKeystore3);
        Assertions.assertEquals("Keystore 3", defaultKeystore3.getLabel());
        wallet.getKeystores().add(defaultKeystore3);
        Keystore defaultKeystore4 = new Keystore("Keystore");
        wallet.makeLabelsUnique(defaultKeystore4);
        Assertions.assertEquals("Keystore 4", defaultKeystore4.getLabel());
        wallet.getKeystores().add(defaultKeystore4);
        Keystore defaultKeystore5 = new Keystore("Keystore 3");
        wallet.makeLabelsUnique(defaultKeystore5);
        Assertions.assertEquals("Keystore 3 2", defaultKeystore5.getLabel());
        wallet.getKeystores().add(defaultKeystore5);

        Keystore keystore6 = new Keystore("Coldcard -1");
        wallet.makeLabelsUnique(keystore6);
        Assertions.assertEquals("Coldcard -1 2", keystore6.getLabel());
        wallet.getKeystores().add(keystore6);

        Keystore longKeystore1 = new Keystore("1234567890ABCDEFG");
        wallet.getKeystores().add(longKeystore1);
        Keystore longKeystore2 = new Keystore("1234567890ABCDEFG");
        wallet.makeLabelsUnique(longKeystore2);
        Assertions.assertEquals("1234567890ABCD 1", longKeystore1.getLabel());
        Assertions.assertEquals("1234567890ABCD 2", longKeystore2.getLabel());
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

        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Assertions.assertEquals("12kTQjuWDp7Uu6PwY6CsS1KLTt3d1DBHZa", receive0.getAddress().toString());
        WalletNode receive1 = new WalletNode(wallet, KeyPurpose.RECEIVE, 1);
        Assertions.assertEquals("1HbQwQCitHQxVtP39isXmUdHx7hQCZovrK", receive1.getAddress().toString());
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

        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Assertions.assertEquals("3NZLE4TntsjtcZ5MbrfxwtYo9meBVybVQj", receive0.getAddress().toString());
        WalletNode receive1 = new WalletNode(wallet, KeyPurpose.RECEIVE, 1);
        Assertions.assertEquals("32YBBuRsp8XTeLx4T6BmD2L4nANGaNDkSg", receive1.getAddress().toString());
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

        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Assertions.assertEquals("bc1quvxdut936uswuxwxrk6nvjmgwxh463r0fjwn55", receive0.getAddress().toString());
        WalletNode receive1 = new WalletNode(wallet, KeyPurpose.RECEIVE, 1);
        Assertions.assertEquals("bc1q95j2862dz7mqpraw6qdjc70gumyu5z7adgq9x9", receive1.getAddress().toString());
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
        Assertions.assertEquals("xprv9s21ZrQH143K4G3jeUxf7h93qLeinXNULjjaef1yZFXpoc5D16iHEFkgJ7ThkWzAEBwNNwyJFtrVhJVJRjCc9ew76JrgsVoXT4VYHJBbbSV", keystore.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6DLZWwJhGmq2SwdAytDWhCUrM4MojYSLHhHMZ1sob9UGXnSvgczEL7zV1wtcy9qcH6yduKMp1bPWcSxxSmz6LEpw4xTABLL3XwX5KGzkNqZ", keystore.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore);
        Keystore keystore2 = Keystore.fromSeed(seed2, ScriptType.P2PKH.getDefaultDerivation());
        Assertions.assertEquals("xprv9s21ZrQH143K4FNcBwXNXfzVNskpoRS7cf4jQTLrhbPkhhXp8hz4QRXT62HziiHziM3Pxyd2Qx3UQkoRpcDu2BauuJJRdyrduXBJGgjAgFx", keystore2.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6ChqMsFBYpJiJYzcJgEvddHtbZr1mTaE1o4RbhFRBAYVxN8SScGb9kjwkXtM33JKejR16gBZhNbkV14AccetR5u2McnCgTCpDBfa8hee9v8", keystore2.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore2);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI, ScriptType.P2SH, wallet.getKeystores(), 2));

        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Assertions.assertEquals("38kq6yz4VcYymTExQPY3gppbz38mtPLveK", receive0.getAddress().toString());
        WalletNode receive1 = new WalletNode(wallet, KeyPurpose.CHANGE, 1);
        Assertions.assertEquals("3EdKaNsnjBTBggWcSMRyVju6GbHWy68mAH", receive1.getAddress().toString());
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
        Assertions.assertEquals("xprv9s21ZrQH143K4G3jeUxf7h93qLeinXNULjjaef1yZFXpoc5D16iHEFkgJ7ThkWzAEBwNNwyJFtrVhJVJRjCc9ew76JrgsVoXT4VYHJBbbSV", keystore.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6DLZWwJhGmq2SwdAytDWhCUrM4MojYSLHhHMZ1sob9UGXnSvgczEL7zV1wtcy9qcH6yduKMp1bPWcSxxSmz6LEpw4xTABLL3XwX5KGzkNqZ", keystore.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore);
        Keystore keystore2 = Keystore.fromSeed(seed2, ScriptType.P2PKH.getDefaultDerivation());
        Assertions.assertEquals("xprv9s21ZrQH143K4FNcBwXNXfzVNskpoRS7cf4jQTLrhbPkhhXp8hz4QRXT62HziiHziM3Pxyd2Qx3UQkoRpcDu2BauuJJRdyrduXBJGgjAgFx", keystore2.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6ChqMsFBYpJiJYzcJgEvddHtbZr1mTaE1o4RbhFRBAYVxN8SScGb9kjwkXtM33JKejR16gBZhNbkV14AccetR5u2McnCgTCpDBfa8hee9v8", keystore2.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore2);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI, ScriptType.P2SH_P2WSH, wallet.getKeystores(), 2));

        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Assertions.assertEquals("3Mw8xqAHh8g3eBvh7q1UEUmoexqdXDK9Tf", receive0.getAddress().toString());
        WalletNode receive1 = new WalletNode(wallet, KeyPurpose.CHANGE, 1);
        Assertions.assertEquals("35dFo1ivJ8jyHpyf42MWvnYf5LBU8Siren", receive1.getAddress().toString());
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
        Assertions.assertEquals("xprv9s21ZrQH143K4G3jeUxf7h93qLeinXNULjjaef1yZFXpoc5D16iHEFkgJ7ThkWzAEBwNNwyJFtrVhJVJRjCc9ew76JrgsVoXT4VYHJBbbSV", keystore.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6DLZWwJhGmq2SwdAytDWhCUrM4MojYSLHhHMZ1sob9UGXnSvgczEL7zV1wtcy9qcH6yduKMp1bPWcSxxSmz6LEpw4xTABLL3XwX5KGzkNqZ", keystore.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore);
        Keystore keystore2 = Keystore.fromSeed(seed2, ScriptType.P2PKH.getDefaultDerivation());
        Assertions.assertEquals("xprv9s21ZrQH143K4FNcBwXNXfzVNskpoRS7cf4jQTLrhbPkhhXp8hz4QRXT62HziiHziM3Pxyd2Qx3UQkoRpcDu2BauuJJRdyrduXBJGgjAgFx", keystore2.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6ChqMsFBYpJiJYzcJgEvddHtbZr1mTaE1o4RbhFRBAYVxN8SScGb9kjwkXtM33JKejR16gBZhNbkV14AccetR5u2McnCgTCpDBfa8hee9v8", keystore2.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore2);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI, ScriptType.P2WSH, wallet.getKeystores(), 2));

        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Assertions.assertEquals("bc1q20e4vm656h5lvmngz9ztz6hjzftvh39yzngqhuqzk8qzj7tqnzaqgclrwc", receive0.getAddress().toString());
        WalletNode receive1 = new WalletNode(wallet, KeyPurpose.CHANGE, 1);
        Assertions.assertEquals("bc1q2epdx7dplwaas2jucfrzmxm8350rqh68hs6vqreysku80ye44mfqla85f2", receive1.getAddress().toString());
    }

    @Test
    public void testHighDerivationPath() {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE);
        wallet.setScriptType(ScriptType.P2WPKH);
        Keystore keystore = new Keystore();
        keystore.setKeyDerivation(new KeyDerivation("ffffffff", "m/84'/0'/2147483646'"));
        ExtendedKey extendedKey = ExtendedKey.fromDescriptor("ypub6WxQGZTrBdeYSD6ZnSxopCGnuS7dhbqc72S3sbjdFjxf8eBR3EJDB3iDMhny2tKogZnpaJcjoHC6zF5Cz1jSMrFFR1wrqfA1MFsWP3ACotd");
        keystore.setExtendedPublicKey(extendedKey);
        wallet.getKeystores().add(keystore);

        List<ChildNumber> derivation = List.of(keystore.getExtendedPublicKey().getKeyChildNumber(), new ChildNumber(0));
        Assertions.assertEquals("027ecc656f4b91b92881b6f07cf876cd2e42b20df7acc4df54fc3315fbb2d13e1c", Utils.bytesToHex(extendedKey.getKey(derivation).getPubKey()));

        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Assertions.assertEquals("bc1qarzeu6ncapyvjzdeayjq8vnzp6uvcn4eaeuuqq", receive0.getAddress().toString());
    }
}
