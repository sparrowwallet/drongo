package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.address.InvalidAddressException;
import com.sparrowwallet.drongo.bip47.PaymentCodeTest;
import com.sparrowwallet.drongo.crypto.*;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTOutput;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.silentpayments.InvalidSilentPaymentException;
import com.sparrowwallet.drongo.silentpayments.SilentPayment;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentAddress;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentScanAddress;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

public class WalletTest {
    //An unrelated silent payments wallet to send to
    private static final String SP_SCAN_ADDRESS = "spscan1qu6d9s9lfd3a99nckpjw7as602lg0950wvcfwg7g4kakhsp32r57qx4853d0ylm42uewydgx6xgz0v20hgthsk2kr84f96jls3q0jywktrv8us5";

    @Test
    public void encryptTest() throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2PKH);
        Keystore keystore = Keystore.fromSeed(seed, PolicyType.SINGLE_HD, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2PKH, wallet.getKeystores(), 1));

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
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2PKH);
        Keystore keystore = Keystore.fromSeed(seed, PolicyType.SINGLE_HD, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2PKH, wallet.getKeystores(), 1));

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
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2SH_P2WPKH);
        Keystore keystore = Keystore.fromSeed(seed, PolicyType.SINGLE_HD, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2SH_P2WPKH, wallet.getKeystores(), 1));

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
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2WPKH);
        Keystore keystore = Keystore.fromSeed(seed, PolicyType.SINGLE_HD, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, wallet.getKeystores(), 1));

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
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2SH);
        Keystore keystore = Keystore.fromSeed(seed, PolicyType.SINGLE_HD, ScriptType.P2PKH.getDefaultDerivation());
        Assertions.assertEquals("xprv9s21ZrQH143K4G3jeUxf7h93qLeinXNULjjaef1yZFXpoc5D16iHEFkgJ7ThkWzAEBwNNwyJFtrVhJVJRjCc9ew76JrgsVoXT4VYHJBbbSV", keystore.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6DLZWwJhGmq2SwdAytDWhCUrM4MojYSLHhHMZ1sob9UGXnSvgczEL7zV1wtcy9qcH6yduKMp1bPWcSxxSmz6LEpw4xTABLL3XwX5KGzkNqZ", keystore.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore);
        Keystore keystore2 = Keystore.fromSeed(seed2, PolicyType.SINGLE_HD, ScriptType.P2PKH.getDefaultDerivation());
        Assertions.assertEquals("xprv9s21ZrQH143K4FNcBwXNXfzVNskpoRS7cf4jQTLrhbPkhhXp8hz4QRXT62HziiHziM3Pxyd2Qx3UQkoRpcDu2BauuJJRdyrduXBJGgjAgFx", keystore2.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6ChqMsFBYpJiJYzcJgEvddHtbZr1mTaE1o4RbhFRBAYVxN8SScGb9kjwkXtM33JKejR16gBZhNbkV14AccetR5u2McnCgTCpDBfa8hee9v8", keystore2.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore2);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2SH, wallet.getKeystores(), 2));

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
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2SH_P2WSH);
        Keystore keystore = Keystore.fromSeed(seed, PolicyType.SINGLE_HD, ScriptType.P2PKH.getDefaultDerivation());
        Assertions.assertEquals("xprv9s21ZrQH143K4G3jeUxf7h93qLeinXNULjjaef1yZFXpoc5D16iHEFkgJ7ThkWzAEBwNNwyJFtrVhJVJRjCc9ew76JrgsVoXT4VYHJBbbSV", keystore.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6DLZWwJhGmq2SwdAytDWhCUrM4MojYSLHhHMZ1sob9UGXnSvgczEL7zV1wtcy9qcH6yduKMp1bPWcSxxSmz6LEpw4xTABLL3XwX5KGzkNqZ", keystore.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore);
        Keystore keystore2 = Keystore.fromSeed(seed2, PolicyType.SINGLE_HD, ScriptType.P2PKH.getDefaultDerivation());
        Assertions.assertEquals("xprv9s21ZrQH143K4FNcBwXNXfzVNskpoRS7cf4jQTLrhbPkhhXp8hz4QRXT62HziiHziM3Pxyd2Qx3UQkoRpcDu2BauuJJRdyrduXBJGgjAgFx", keystore2.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6ChqMsFBYpJiJYzcJgEvddHtbZr1mTaE1o4RbhFRBAYVxN8SScGb9kjwkXtM33JKejR16gBZhNbkV14AccetR5u2McnCgTCpDBfa8hee9v8", keystore2.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore2);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2SH_P2WSH, wallet.getKeystores(), 2));

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
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        Keystore keystore = Keystore.fromSeed(seed, PolicyType.SINGLE_HD, ScriptType.P2PKH.getDefaultDerivation());
        Assertions.assertEquals("xprv9s21ZrQH143K4G3jeUxf7h93qLeinXNULjjaef1yZFXpoc5D16iHEFkgJ7ThkWzAEBwNNwyJFtrVhJVJRjCc9ew76JrgsVoXT4VYHJBbbSV", keystore.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6DLZWwJhGmq2SwdAytDWhCUrM4MojYSLHhHMZ1sob9UGXnSvgczEL7zV1wtcy9qcH6yduKMp1bPWcSxxSmz6LEpw4xTABLL3XwX5KGzkNqZ", keystore.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore);
        Keystore keystore2 = Keystore.fromSeed(seed2, PolicyType.SINGLE_HD, ScriptType.P2PKH.getDefaultDerivation());
        Assertions.assertEquals("xprv9s21ZrQH143K4FNcBwXNXfzVNskpoRS7cf4jQTLrhbPkhhXp8hz4QRXT62HziiHziM3Pxyd2Qx3UQkoRpcDu2BauuJJRdyrduXBJGgjAgFx", keystore2.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("xpub6ChqMsFBYpJiJYzcJgEvddHtbZr1mTaE1o4RbhFRBAYVxN8SScGb9kjwkXtM33JKejR16gBZhNbkV14AccetR5u2McnCgTCpDBfa8hee9v8", keystore2.getExtendedPublicKey().toString());
        wallet.getKeystores().add(keystore2);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));

        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Assertions.assertEquals("bc1q20e4vm656h5lvmngz9ztz6hjzftvh39yzngqhuqzk8qzj7tqnzaqgclrwc", receive0.getAddress().toString());
        WalletNode receive1 = new WalletNode(wallet, KeyPurpose.CHANGE, 1);
        Assertions.assertEquals("bc1q2epdx7dplwaas2jucfrzmxm8350rqh68hs6vqreysku80ye44mfqla85f2", receive1.getAddress().toString());
    }

    @Test
    public void testHighDerivationPath() {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_HD);
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

    @Test
    public void testWalletNodeTweakCopy() {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_SP);
        wallet.setScriptType(ScriptType.P2TR);

        WalletNode node = new WalletNode(wallet, "m/0");
        byte[] tweak = Utils.hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
        node.setSilentPaymentTweak(tweak);

        WalletNode copy = node.copy(wallet);
        Assertions.assertArrayEquals(tweak, copy.getSilentPaymentTweak());
    }

    @Test
    public void testKeystoreGetPubKeyWithSpTweak() {
        ECKey scanKey = ECKey.fromPrivate(Utils.hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"));
        ECKey spendKey = ECKey.fromPrivate(Utils.hexToBytes("b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"));
        SilentPaymentScanAddress spAddr = new SilentPaymentScanAddress(scanKey, ECKey.fromPublicOnly(spendKey));

        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_SP);
        wallet.setScriptType(ScriptType.P2TR);
        Keystore keystore = new Keystore();
        keystore.setSilentPaymentScanAddress(spAddr);
        keystore.setKeyDerivation(new KeyDerivation("deadbeef", "m/352'/0'/0'"));
        wallet.getKeystores().add(keystore);

        byte[] tweak = Utils.hexToBytes("c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
        WalletNode node = new WalletNode(wallet, "m/0");
        node.setSilentPaymentTweak(tweak);

        // Compute expected: B_spend + tweak*G
        ECKey tweakPoint = ECKey.fromPublicOnly(ECKey.fromPrivate(tweak));
        ECKey expectedOutputKey = ECKey.fromPublicOnly(spendKey).add(tweakPoint, true);

        ECKey result = keystore.getPubKey(node);
        Assertions.assertArrayEquals(expectedOutputKey.getPubKey(), result.getPubKey());
    }

    @Test
    public void testWalletGetAddressForSp() {
        ECKey scanKey = ECKey.fromPrivate(Utils.hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"));
        ECKey spendKey = ECKey.fromPrivate(Utils.hexToBytes("b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"));
        SilentPaymentScanAddress spAddr = new SilentPaymentScanAddress(scanKey, ECKey.fromPublicOnly(spendKey));

        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_SP);
        wallet.setScriptType(ScriptType.P2TR);
        Keystore keystore = new Keystore();
        keystore.setSilentPaymentScanAddress(spAddr);
        keystore.setKeyDerivation(new KeyDerivation("deadbeef", "m/352'/0'/0'"));
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_SP, ScriptType.P2TR, wallet.getKeystores(), 1));

        byte[] tweak = Utils.hexToBytes("c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
        WalletNode node = new WalletNode(wallet, "m/0");
        node.setSilentPaymentTweak(tweak);

        // Compute expected address: P2TR address from x-coord of (B_spend + tweak*G)
        ECKey tweakPoint = ECKey.fromPublicOnly(ECKey.fromPrivate(tweak));
        ECKey outputKey = ECKey.fromPublicOnly(spendKey).add(tweakPoint, true);
        Address expectedAddress = ScriptType.P2TR.getAddress(outputKey.getPubKeyXCoord());

        Address result = wallet.getAddress(node);
        Assertions.assertEquals(expectedAddress, result);
    }

    @Test
    public void testFillToIndexNoOpForSp() {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_SP);
        wallet.setScriptType(ScriptType.P2TR);

        WalletNode purposeNode = wallet.getNode(KeyPurpose.RECEIVE);
        Assertions.assertTrue(purposeNode.getChildren().isEmpty());
        Assertions.assertTrue(purposeNode.fillToIndex(10).isEmpty());
        Assertions.assertTrue(purposeNode.getChildren().isEmpty());
    }

    @Test
    public void testAddSilentPaymentChildSetsTweak() {
        Wallet wallet = buildValidSpWallet();
        WalletNode purposeNode = wallet.getNode(KeyPurpose.RECEIVE);

        byte[] tweak = Utils.hexToBytes("c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
        WalletNode addressNode = purposeNode.addSilentPaymentChild(wallet, 0, tweak);

        Assertions.assertArrayEquals(tweak, addressNode.getSilentPaymentTweak());
        Assertions.assertEquals(1, purposeNode.getChildren().size());
        Assertions.assertNotNull(wallet.getAddress(addressNode));
    }

    @Test
    public void testAddSilentPaymentChildReturnsNullOnDuplicateIndex() {
        Wallet wallet = buildValidSpWallet();
        WalletNode purposeNode = wallet.getNode(KeyPurpose.RECEIVE);

        byte[] firstTweak = Utils.hexToBytes("c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
        byte[] secondTweak = Utils.hexToBytes("d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5");

        WalletNode first = purposeNode.addSilentPaymentChild(wallet, 0, firstTweak);
        WalletNode duplicate = purposeNode.addSilentPaymentChild(wallet, 0, secondTweak);

        Assertions.assertNull(duplicate);
        Assertions.assertEquals(1, purposeNode.getChildren().size());
        Assertions.assertArrayEquals(firstTweak, first.getSilentPaymentTweak());
    }

    @Test
    public void testAddSilentPaymentChildAttachesDetachedLabel() {
        Wallet wallet = buildValidSpWallet();
        WalletNode purposeNode = wallet.getNode(KeyPurpose.RECEIVE);

        byte[] tweak = Utils.hexToBytes("c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");

        // Pre-compute the address the new node will resolve to and stash a detached label for it
        WalletNode probe = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        probe.setSilentPaymentTweak(tweak);
        String expectedAddress = wallet.getAddress(probe).toString();
        wallet.getDetachedLabels().put(expectedAddress, "Restored label");

        WalletNode addressNode = purposeNode.addSilentPaymentChild(wallet, 0, tweak);

        Assertions.assertEquals("Restored label", addressNode.getLabel());
        Assertions.assertFalse(wallet.getDetachedLabels().containsKey(expectedAddress));
    }

    @Test
    public void testRequiredGapLimitNullForSp() {
        Wallet wallet = buildValidSpWallet();
        Assertions.assertNull(wallet.getRequiredGapLimit(null));
    }

    @Test
    public void maxCosignersP2shTest() throws MnemonicException, InvalidWalletException {
        //A 15 cosigner P2SH redeem script is 513 bytes and spendable, so it must keep working
        Wallet wallet = buildMultisigWallet(ScriptType.P2SH, 15);
        wallet.checkWallet();
        WalletNode receive0 = new WalletNode(wallet, KeyPurpose.RECEIVE, 0);
        Assertions.assertEquals(513, ScriptType.MULTISIG.getOutputScript(2, receive0.getPubKeys()).getProgram().length);
        Assertions.assertNotNull(receive0.getAddress());

        //A 16 cosigner P2SH redeem script is 547 bytes, which exceeds the 520 byte maximum script element size and is unspendable
        Wallet oversize = buildMultisigWallet(ScriptType.P2SH, 16);
        InvalidWalletException e = Assertions.assertThrows(InvalidWalletException.class, oversize::checkWallet);
        Assertions.assertTrue(e.getMessage().contains("maximum of 15 cosigners"));
        Assertions.assertFalse(oversize.isValid());

        //Anything bypassing wallet validation must still be rejected when the address or output script is derived
        Script oversizeRedeemScript = ScriptType.MULTISIG.getOutputScript(2, new WalletNode(oversize, KeyPurpose.RECEIVE, 0).getPubKeys());
        Assertions.assertEquals(547, oversizeRedeemScript.getProgram().length);
        Assertions.assertThrows(ProtocolException.class, () -> ScriptType.P2SH.getAddress(oversizeRedeemScript));
        Assertions.assertThrows(ProtocolException.class, () -> ScriptType.P2SH.getOutputScript(oversizeRedeemScript));
    }

    @Test
    public void maxCosignersSegwitTest() throws MnemonicException, InvalidWalletException {
        //The witness script is exempt from the maximum script element size, so 16 cosigners remains valid for both segwit types
        for(ScriptType scriptType : List.of(ScriptType.P2WSH, ScriptType.P2SH_P2WSH)) {
            Wallet wallet = buildMultisigWallet(scriptType, 16);
            wallet.checkWallet();
            Assertions.assertNotNull(new WalletNode(wallet, KeyPurpose.RECEIVE, 0).getAddress());
        }
    }

    @Test
    public void testMalformedOpReturnDoesNotBreakCoinSelection() {
        Wallet wallet = buildFundedWallet(new Script(List.of(ScriptChunk.fromOpcode(ScriptOpCodes.OP_RETURN), ScriptChunk.fromOpcode(ScriptOpCodes.OP_1))), true);

        List<OutputGroup> outputGroups = wallet.getGroupedUtxos(Collections.emptyList(), 1.0d, 1.0d, false);
        Assertions.assertEquals(1, outputGroups.size());
        Assertions.assertFalse(outputGroups.get(0).isSpendLast());
    }

    @Test
    public void testUnknownFundingTransactionDoesNotBreakCoinSelection() {
        Wallet wallet = buildFundedWallet(new Script(List.of(ScriptChunk.fromOpcode(ScriptOpCodes.OP_RETURN), ScriptChunk.fromData(PaymentCodeTest.getNotificationPayload()))), false);

        List<OutputGroup> outputGroups = wallet.getGroupedUtxos(Collections.emptyList(), 1.0d, 1.0d, false);
        Assertions.assertEquals(1, outputGroups.size());
        Assertions.assertFalse(outputGroups.get(0).isSpendLast());
    }

    @Test
    public void testNotificationChangeIsSpentLast() {
        Wallet wallet = buildFundedWallet(new Script(List.of(ScriptChunk.fromOpcode(ScriptOpCodes.OP_RETURN), ScriptChunk.fromData(PaymentCodeTest.getNotificationPayload()))), true);

        List<OutputGroup> outputGroups = wallet.getGroupedUtxos(Collections.emptyList(), 1.0d, 1.0d, false);
        Assertions.assertEquals(1, outputGroups.size());
        Assertions.assertTrue(outputGroups.get(0).isSpendLast());
    }

    private Wallet buildMultisigWallet(ScriptType scriptType, int cosigners) throws MnemonicException {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(scriptType);

        for(int i = 0; i < cosigners; i++) {
            byte[] entropy = Utils.hexToBytes(String.format("%032x", i + 1));
            DeterministicSeed seed = new DeterministicSeed(entropy, "", 0);
            Keystore keystore = Keystore.fromSeed(seed, PolicyType.MULTI_HD, scriptType.getDefaultDerivation());
            keystore.setLabel("Keystore " + (i + 1));
            wallet.getKeystores().add(keystore);
        }

        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, scriptType, wallet.getKeystores(), 2));
        return wallet;
    }

    @Test
    public void testSilentPaymentOutputIsSizedForFee() throws InsufficientFundsException {
        Wallet wallet = buildSpendingWallet();
        SilentPaymentAddress spAddress = buildValidSpWallet().getSilentPaymentScanAddress().getSilentPaymentAddress();
        WalletTransaction walletTransaction = createSpendingTransaction(wallet, new SilentPayment(spAddress, "SP payment", 100000L, false), 10.0d);

        TransactionOutput spOutput = walletTransaction.getTransaction().getOutputs().stream()
                .filter(txOutput -> txOutput.getValue() == 100000L).findFirst().orElseThrow();
        Assertions.assertEquals(0, spOutput.getScriptBytes().length, "A silent payment output script is only computed when the transaction is signed");

        double estimatedVSize = walletTransaction.getVirtualSize();
        Assertions.assertEquals(10.0d, walletTransaction.getFeeRate(), 0.1d, "The transaction must pay the chosen fee rate");

        //Computing the output script, as computeSilentPaymentOutputs does after signing, must arrive at the size the fee was derived from
        spOutput.setScriptBytes(ScriptType.P2TR.getOutputScript(Utils.hexToBytes("1111111111111111111111111111111111111111111111111111111111111111")).getProgram());
        Assertions.assertEquals(estimatedVSize, walletTransaction.getTransaction().getVirtualSize(), "The estimate must be the size of the broadcast transaction");
    }

    @Test
    public void testSilentPaymentChangeOutputIsSizedForFee() throws InsufficientFundsException {
        //A silent payments wallet sending to another silent payment address has two placeholder outputs, the payment and its own change
        Wallet wallet = buildFundedSpWallet();
        SilentPaymentAddress spAddress = SilentPaymentScanAddress.fromKeyString(SP_SCAN_ADDRESS).getSilentPaymentAddress();
        WalletTransaction walletTransaction = createSpendingTransaction(wallet, new SilentPayment(spAddress, "SP payment", 100000L, false), 10.0d);
        Assertions.assertEquals(2, walletTransaction.getTransaction().getOutputs().size(), "The payment should require a change output");
        Assertions.assertTrue(walletTransaction.getTransaction().getOutputs().stream().allMatch(txOutput -> txOutput.getScriptBytes().length == 0), "Both outputs should be placeholders");

        double estimatedVSize = walletTransaction.getVirtualSize();
        Assertions.assertEquals(10.0d, walletTransaction.getFeeRate(), 0.1d);

        for(TransactionOutput txOutput : walletTransaction.getTransaction().getOutputs()) {
            if(txOutput.getScriptBytes().length == 0) {
                txOutput.setScriptBytes(ScriptType.P2TR.getOutputScript(Utils.hexToBytes("1111111111111111111111111111111111111111111111111111111111111111")).getProgram());
            }
        }

        Assertions.assertEquals(estimatedVSize, walletTransaction.getTransaction().getVirtualSize());
    }

    @Test
    public void testUnresolvedSilentPaymentOutputVSize() throws InsufficientFundsException {
        Wallet wallet = buildSpendingWallet();
        SilentPaymentAddress spAddress = SilentPaymentScanAddress.fromKeyString(SP_SCAN_ADDRESS).getSilentPaymentAddress();
        WalletTransaction walletTransaction = createSpendingTransaction(wallet, new SilentPayment(spAddress, "SP payment", 100000L, false), 10.0d);

        //A transaction sized from an unsigned PSBT is short of what computing the silent payment output scripts adds to it
        PSBT psbt = walletTransaction.createPSBT();
        double unsignedVSize = psbt.getTransaction().getVirtualSize();
        for(PSBTOutput psbtOutput : psbt.getPsbtOutputs()) {
            if(psbtOutput.getSilentPaymentAddress() != null) {
                psbtOutput.setScript(ScriptType.P2TR.getOutputScript(Utils.hexToBytes("1111111111111111111111111111111111111111111111111111111111111111")));
            }
        }

        Assertions.assertEquals(unsignedVSize + SilentPayment.OUTPUT_SCRIPT_LENGTH, psbt.getTransaction().getVirtualSize());
    }

    @Test
    public void testComputedSilentPaymentOutputIsNotSizedTwice() throws InsufficientFundsException {
        //A wallet transaction read back from a signed PSBT holds silent payment outputs whose scripts have been computed, and is sized as it stands
        Wallet wallet = buildSpendingWallet();
        SilentPaymentAddress spAddress = SilentPaymentScanAddress.fromKeyString(SP_SCAN_ADDRESS).getSilentPaymentAddress();
        WalletTransaction walletTransaction = createSpendingTransaction(wallet, new SilentPayment(spAddress, "SP payment", 100000L, false), 10.0d);

        TransactionOutput spOutput = walletTransaction.getTransaction().getOutputs().stream()
                .filter(txOutput -> txOutput.getValue() == 100000L).findFirst().orElseThrow();
        Script computedScript = ScriptType.P2TR.getOutputScript(Utils.hexToBytes("1111111111111111111111111111111111111111111111111111111111111111"));
        spOutput.setScriptBytes(computedScript.getProgram());

        List<WalletTransaction.Output> outputs = walletTransaction.getOutputs();
        WalletTransaction computed = new WalletTransaction(wallet, walletTransaction.getTransaction(), Collections.emptyList(), walletTransaction.getSelectedUtxoSets(),
                walletTransaction.getPayments(), outputs, walletTransaction.getFee());

        Assertions.assertTrue(outputs.stream().anyMatch(output -> output instanceof WalletTransaction.SilentPaymentOutput));
        Assertions.assertEquals(computed.getTransaction().getVirtualSize(), computed.getVirtualSize(), "A computed silent payment output must not be sized twice");
        Assertions.assertEquals(10.0d, computed.getFeeRate(), 0.1d);
    }

    @Test
    public void testHdOutputSizeIsUnchanged() throws InsufficientFundsException, InvalidAddressException {
        Wallet wallet = buildSpendingWallet();
        WalletTransaction walletTransaction = createSpendingTransaction(wallet, new Payment(Address.fromString("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), "Payment", 100000L, false), 10.0d);

        Assertions.assertEquals(walletTransaction.getTransaction().getVirtualSize(), walletTransaction.getVirtualSize(), "A transaction without silent payment outputs needs no adjustment");
        Assertions.assertEquals(10.0d, walletTransaction.getFeeRate(), 0.1d);
    }

    @Test
    public void testSilentPaymentNodeOutputDescriptor() {
        Wallet wallet = buildValidSpWallet();
        WalletNode addressNode = wallet.getNode(KeyPurpose.RECEIVE).addSilentPaymentChild(wallet, 0, Utils.hexToBytes("c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));

        //The node key is already the output key, so the descriptor must be the raw form that does not tweak it again
        String outputDescriptor = wallet.getOutputDescriptor(addressNode);
        String outputKey = Utils.bytesToHex(addressNode.getPubKey().getPubKeyXCoord());
        Assertions.assertEquals("rawtr(" + outputKey + ")", outputDescriptor);

        //The key the descriptor names must be the one the address pays to
        Assertions.assertEquals(outputKey, Utils.bytesToHex(ScriptType.P2TR.getPublicKeyFromScript(wallet.getOutputScript(addressNode)).getPubKeyXCoord()));
    }

    @Test
    public void testHdNodeOutputDescriptorIsUnchanged() throws MnemonicException {
        Wallet wallet = buildSigningWallet(ScriptType.P2TR);
        WalletNode addressNode = wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();

        //A taproot key is the internal key, which tr() tweaks to arrive at the address
        String outputDescriptor = wallet.getOutputDescriptor(addressNode);
        Assertions.assertEquals("tr(" + Utils.bytesToHex(addressNode.getPubKey().getPubKeyXCoord()) + ")", outputDescriptor);
        Assertions.assertNotEquals(Utils.bytesToHex(addressNode.getPubKey().getPubKeyXCoord()),
                Utils.bytesToHex(ScriptType.P2TR.getPublicKeyFromScript(wallet.getOutputScript(addressNode)).getPubKeyXCoord()));
    }

    @Test
    public void testSignatureOverUnresolvedSilentPaymentOutputIsRejected() throws InsufficientFundsException {
        Wallet wallet = buildSpendingWallet();
        SilentPaymentAddress spAddress = SilentPaymentScanAddress.fromKeyString(SP_SCAN_ADDRESS).getSilentPaymentAddress();
        WalletTransaction walletTransaction = createSpendingTransaction(wallet, new SilentPayment(spAddress, "SP payment", 100000L, false), 10.0d);
        PSBT psbt = walletTransaction.createPSBT();

        //Unresolved outputs are not themselves a problem, being what the wallet hands a signer to compute
        Assertions.assertDoesNotThrow(() -> wallet.verifySilentPaymentScripts(psbt));

        //A signer that returns signatures without computing them has committed to an empty output script
        PSBTInput psbtInput = psbt.getPsbtInputs().getFirst();
        psbtInput.getPartialSignatures().put(ECKey.fromPublicOnly(ECKey.fromPrivate(Utils.hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")).getPubKey()),
                TransactionSignature.dummy(ScriptType.P2WPKH.getSignatureType()));

        Assertions.assertThrows(InvalidSilentPaymentException.class, () -> wallet.verifySilentPaymentScripts(psbt));
    }

    @Test
    public void testSignatureWithoutSilentPaymentOutputsIsAccepted() throws InsufficientFundsException, InvalidAddressException {
        Wallet wallet = buildSpendingWallet();
        WalletTransaction walletTransaction = createSpendingTransaction(wallet, new Payment(Address.fromString("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), "Payment", 100000L, false), 10.0d);
        PSBT psbt = walletTransaction.createPSBT();

        psbt.getPsbtInputs().getFirst().getPartialSignatures().put(ECKey.fromPublicOnly(ECKey.fromPrivate(Utils.hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")).getPubKey()),
                TransactionSignature.dummy(ScriptType.P2WPKH.getSignatureType()));

        //Called directly rather than through the single argument overload, which returns before reaching the check for
        //a PSBT carrying no silent payment outputs. A caller bypassing that wrapper must still not have its signatures refused
        Assertions.assertDoesNotThrow(() -> wallet.verifySilentPaymentScripts(psbt, wallet.getSigningNodes(psbt)));
    }

    private Wallet buildFundedSpWallet() {
        Wallet wallet = buildValidSpWallet();
        wallet.setStoredBlockHeight(800006);
        WalletNode addressNode = wallet.getNode(KeyPurpose.RECEIVE).addSilentPaymentChild(wallet, 0, Utils.hexToBytes("c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));

        Transaction funding = new Transaction();
        funding.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        funding.addOutput(1000000L, wallet.getAddress(addressNode));
        wallet.updateTransactions(Map.of(funding.getTxId(), new BlockTransaction(funding.getTxId(), 800000, new Date(), 0L, funding)));
        addressNode.getTransactionOutputs().add(new BlockTransactionHashIndex(funding.getTxId(), 800000, new Date(), 0L, 0, 1000000L));

        return wallet;
    }

    private Wallet buildSpendingWallet() {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2WPKH);
        Keystore keystore = new Keystore();
        keystore.setKeyDerivation(new KeyDerivation("00000000", "m/84'/0'/0'"));
        keystore.setExtendedPublicKey(ExtendedKey.fromDescriptor("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"));
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, wallet.getKeystores(), 1));
        wallet.setStoredBlockHeight(800006);

        WalletNode receiveNode = wallet.getNode(KeyPurpose.RECEIVE);
        receiveNode.fillToIndex(0);
        WalletNode addressNode = receiveNode.getChildren().iterator().next();

        Transaction funding = new Transaction();
        funding.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        funding.addOutput(1000000L, wallet.getAddress(addressNode));
        wallet.updateTransactions(Map.of(funding.getTxId(), new BlockTransaction(funding.getTxId(), 800000, new Date(), 0L, funding)));
        addressNode.getTransactionOutputs().add(new BlockTransactionHashIndex(funding.getTxId(), 800000, new Date(), 0L, 0, 1000000L));

        return wallet;
    }

    private WalletTransaction createSpendingTransaction(Wallet wallet, Payment payment, double feeRate) throws InsufficientFundsException {
        TransactionParameters params = new TransactionParameters(List.of(new PriorityUtxoSelector(800006)), Collections.emptyList(), List.of(payment), Collections.emptyList(),
                Collections.emptySet(), feeRate, 1.0d, 1.0d, null, 800006, false, false, true);

        return wallet.createWalletTransaction(params);
    }

    private Wallet buildValidSpWallet() {
        ECKey scanKey = ECKey.fromPrivate(Utils.hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"));
        ECKey spendKey = ECKey.fromPrivate(Utils.hexToBytes("b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"));
        SilentPaymentScanAddress spAddr = new SilentPaymentScanAddress(scanKey, ECKey.fromPublicOnly(spendKey));

        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_SP);
        wallet.setScriptType(ScriptType.P2TR);
        Keystore keystore = new Keystore();
        keystore.setSilentPaymentScanAddress(spAddr);
        keystore.setKeyDerivation(new KeyDerivation("deadbeef", "m/352'/0'/0'"));
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_SP, ScriptType.P2TR, wallet.getKeystores(), 1));
        return wallet;
    }

    private Wallet buildFundedWallet(Script opReturnScript, boolean addWalletTransaction) {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2WPKH);
        Keystore keystore = new Keystore();
        keystore.setKeyDerivation(new KeyDerivation("00000000", "m/84'/0'/0'"));
        keystore.setExtendedPublicKey(ExtendedKey.fromDescriptor("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"));
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, wallet.getKeystores(), 1));
        wallet.setStoredBlockHeight(800006);

        WalletNode receiveNode = wallet.getNode(KeyPurpose.RECEIVE);
        receiveNode.fillToIndex(0);
        WalletNode addressNode = receiveNode.getChildren().iterator().next();

        //An unsolicited payment to a known receive address, carrying an OP_RETURN output alongside it
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        transaction.addOutput(10000, wallet.getAddress(addressNode));
        transaction.addOutput(0, opReturnScript);

        Date date = new Date();
        if(addWalletTransaction) {
            wallet.updateTransactions(Map.of(transaction.getTxId(), new BlockTransaction(transaction.getTxId(), 800000, date, 0L, transaction)));
        }
        addressNode.setTransactionOutputs(new TreeSet<>(List.of(new BlockTransactionHashIndex(transaction.getTxId(), 800000, date, 0L, 0, 10000))));

        return wallet;
    }

    @Test
    public void testSignedKeystoresSigHashAll() throws MnemonicException {
        Wallet wallet = buildSigningWallet(ScriptType.P2WPKH);
        Transaction transaction = signInput(wallet, SigHash.ALL.value);
        Assertions.assertEquals(1, wallet.getSignedKeystores(transaction).values().stream().mapToInt(Map::size).sum());
    }

    @Test
    public void testSignedKeystoresSigHashSingle() throws MnemonicException {
        Wallet wallet = buildSigningWallet(ScriptType.P2WPKH);
        Transaction transaction = signInput(wallet, SigHash.SINGLE.value);
        Assertions.assertEquals(1, wallet.getSignedKeystores(transaction).values().stream().mapToInt(Map::size).sum());
    }

    @Test
    public void testSignedKeystoresNonCanonicalSigHashFlags() throws MnemonicException {
        Wallet wallet = buildSigningWallet(ScriptType.P2WPKH);
        //Not a defined SigHash value, but SIGHASH_ALL under Bitcoin Core's bit testing
        Transaction transaction = signInput(wallet, (byte)0x41);
        Assertions.assertEquals(1, wallet.getSignedKeystores(transaction).values().stream().mapToInt(Map::size).sum());
    }

    @Test
    public void testSignedKeystoresTaprootSigHashDefault() throws MnemonicException {
        Wallet wallet = buildSigningWallet(ScriptType.P2TR);
        Transaction transaction = signInput(wallet, SigHash.DEFAULT.value);
        Assertions.assertEquals(1, wallet.getSignedKeystores(transaction).values().stream().mapToInt(Map::size).sum());
    }

    @Test
    public void testSignedKeystoresTaprootSigHashAll() throws MnemonicException {
        Wallet wallet = buildSigningWallet(ScriptType.P2TR);
        //A 65 byte key path signature carrying an explicit SIGHASH_ALL, rather than the 64 byte SIGHASH_DEFAULT form
        Transaction transaction = signInput(wallet, SigHash.ALL.value);
        Assertions.assertEquals(1, wallet.getSignedKeystores(transaction).values().stream().mapToInt(Map::size).sum());
    }

    @Test
    public void testSignedKeystoresTaprootSigHashSingle() throws MnemonicException {
        Wallet wallet = buildSigningWallet(ScriptType.P2TR);
        Transaction transaction = signInput(wallet, SigHash.SINGLE.value);
        Assertions.assertEquals(1, wallet.getSignedKeystores(transaction).values().stream().mapToInt(Map::size).sum());
    }

    private Wallet buildSigningWallet(ScriptType scriptType) throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        DeterministicSeed seed = new DeterministicSeed(words, "", 0, DeterministicSeed.Type.BIP39);
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(scriptType);
        wallet.getKeystores().add(Keystore.fromSeed(seed, PolicyType.SINGLE_HD, scriptType.getDefaultDerivation()));
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, scriptType, wallet.getKeystores(), 1));
        wallet.getNode(KeyPurpose.RECEIVE).fillToIndex(0);

        return wallet;
    }

    private Transaction signInput(Wallet wallet, byte sigHashFlags) throws MnemonicException {
        WalletNode addressNode = wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
        Script outputScript = wallet.getOutputScript(addressNode);

        Transaction funding = new Transaction();
        funding.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        funding.addOutput(100000, outputScript);
        wallet.updateTransactions(Map.of(funding.getTxId(), new BlockTransaction(funding.getTxId(), 800000, new Date(), 0L, funding)));

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(funding.getTxId(), 0, new Script(new byte[0]));
        transaction.addOutput(90000, outputScript);

        ECKey key = wallet.getKeystores().getFirst().getKey(addressNode);
        if(wallet.getScriptType() == ScriptType.P2TR) {
            Sha256Hash hash = transaction.hashForTaprootSignature(List.of(funding.getOutputs().getFirst()), 0, false, outputScript, sigHashFlags, null);
            SchnorrSignature schnorrSignature = key.getTweakedOutputKey().signSchnorr(hash);
            TransactionSignature signature = new TransactionSignature(schnorrSignature.r, schnorrSignature.s, TransactionSignature.Type.SCHNORR, sigHashFlags);
            transaction.getInputs().getFirst().setWitness(new TransactionWitness(transaction, signature));
        } else {
            Script scriptCode = ScriptType.P2PKH.getOutputScript(key.getPubKeyHash());
            Sha256Hash hash = transaction.hashForWitnessSignature(0, scriptCode.getProgram(), 100000, sigHashFlags);
            ECDSASignature ecdsaSignature = key.signEcdsa(hash);
            TransactionSignature signature = new TransactionSignature(ecdsaSignature.r, ecdsaSignature.s, TransactionSignature.Type.ECDSA, sigHashFlags);
            transaction.getInputs().getFirst().setWitness(new TransactionWitness(transaction, key, signature));
        }

        return transaction;
    }
}
