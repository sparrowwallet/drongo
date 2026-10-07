package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.HDKeyDerivation;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

public class Bip39MnemonicCodeTest {
    @Test
    public void bip39TwelveWordsTest() throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        List<String> wordlist = Arrays.asList(words.split(" "));

        Bip39MnemonicCode.INSTANCE.check(wordlist);
        byte[] seed = Bip39MnemonicCode.toSeed(wordlist, "");

        Assertions.assertEquals("727ecfcf0bce9d8ec0ef066f7aeb845c271bdd4ee06a37398cebd40dc810140bb620b6c10a8ad671afdceaf37aa55d92d6478f747e8b92430dd938ab5be961dd", Utils.bytesToHex(seed));
    }

    @Test
    public void bip39TwelveWordsInvalidTest() throws MnemonicException {
        String words = "absent absent absent absent absent absent absent absent absent absent absent absent";
        List<String> wordlist = Arrays.asList(words.split(" "));

        Assertions.assertThrows(MnemonicException.MnemonicChecksumException.class, () -> Bip39MnemonicCode.INSTANCE.check(wordlist));
    }

    @Test
    public void bip39TwelveWordsPassphraseTest() throws MnemonicException {
        String words = "arch easily near social civil image seminar monkey engine party promote turtle";
        List<String> wordlist = Arrays.asList(words.split(" "));

        Bip39MnemonicCode.INSTANCE.check(wordlist);
        byte[] seed = Bip39MnemonicCode.toSeed(wordlist, "anotherpass867");

        Assertions.assertEquals("ca50764cda44a2cf52aef3c677bebf26011f9dc2b9fddfed2a8a5a9ecb8542956990a16e6873b7724044e83708d9d3a662b765e8800e6e79b289f51c2bcad756", Utils.bytesToHex(seed));
    }

    @Test
    public void bip39FifteenWordsTest() throws MnemonicException {
        String words = "open grunt omit snap behave inch engine hamster hope increase exotic segment news choose roast";
        List<String> wordlist = Arrays.asList(words.split(" "));

        Bip39MnemonicCode.INSTANCE.check(wordlist);
        byte[] seed = Bip39MnemonicCode.toSeed(wordlist, "");

        Assertions.assertEquals("2174deae5fd315253dc065db7ef97f46957eb68a12505adccfb7f8aca5b63788c587e73430848f85417d9a7d95e6396d2eb3af73c9fb507ebcb9268a5ad47885", Utils.bytesToHex(seed));
    }

    @Test
    public void bip39EighteenWordsTest() throws MnemonicException {
        String words = "mandate lend daring actual health dilemma throw muffin garden pony inherit volume slim visual police supreme bless crush";
        List<String> wordlist = Arrays.asList(words.split(" "));

        Bip39MnemonicCode.INSTANCE.check(wordlist);
        byte[] seed = Bip39MnemonicCode.toSeed(wordlist, "");

        Assertions.assertEquals("04bd65f582e288bbf595213048b06e1552017776d20ca290ac06d840e197bcaaccd4a85a45a41219be4183dd2e521e7a7a2d6aea3069f04e503ef6d9c8dfa651", Utils.bytesToHex(seed));
    }

    @Test
    public void bip39TwentyOneWordsTest() throws MnemonicException {
        String words = "mirror milk file hope drill conduct empty mutual physical easily sell patient green final release excuse name asset update advance resource";
        List<String> wordlist = Arrays.asList(words.split(" "));

        Bip39MnemonicCode.INSTANCE.check(wordlist);
        byte[] seed = Bip39MnemonicCode.toSeed(wordlist, "");

        Assertions.assertEquals("f3a88a437153333f9759f323dfe7910e6a649c34da5800e6c978d77baad54b67b06eab17c0107243f3e8b395a2de98c910e9528127539efda2eea5ae50e94019", Utils.bytesToHex(seed));
    }

    @Test
    public void bip39TwentyFourWordsTest() throws MnemonicException {
        String words = "earth easily dwarf dance forum muscle brick often huge base long steel silk frost quiz liquid echo adapt annual expand slim rookie venture oval";
        List<String> wordlist = Arrays.asList(words.split(" "));

        Bip39MnemonicCode.INSTANCE.check(wordlist);
        byte[] seed = Bip39MnemonicCode.toSeed(wordlist, "");

        Assertions.assertEquals("60f825219a1fcfa479de28435e9bf2aa5734e212982daee582ca0427ad6141c65be9863c3ce0f18e2b173083ea49dcf47d07148734a5f748ac60d470cee6a2bc", Utils.bytesToHex(seed));
    }

    @Test
    public void bip39TwentyFourWordsPassphraseTest() throws MnemonicException {
        String words = "earth easily dwarf dance forum muscle brick often huge base long steel silk frost quiz liquid echo adapt annual expand slim rookie venture oval";
        List<String> wordlist = Arrays.asList(words.split(" "));

        Bip39MnemonicCode.INSTANCE.check(wordlist);
        byte[] seed = Bip39MnemonicCode.toSeed(wordlist, "thispass");

        Assertions.assertEquals("a652d123f421f56257391af26063e900619678b552dafd3850e699f6da0667269bbcaebb0509557481db29607caac0294b3cd337d740174cfa05f552fe9e0272", Utils.bytesToHex(seed));
    }

    @Test
    public void bip39TestVector1() throws MnemonicException {
        String words = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always";
        List<String> wordlist = Arrays.asList(words.split(" "));

        Bip39MnemonicCode.INSTANCE.check(wordlist);
        byte[] seed = Bip39MnemonicCode.toSeed(wordlist, "TREZOR");

        Assertions.assertEquals("107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65", Utils.bytesToHex(seed));
    }

    @Test
    public void bip39TestVector2() throws MnemonicException {
        String words = "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog";
        List<String> wordlist = Arrays.asList(words.split(" "));

        Bip39MnemonicCode.INSTANCE.check(wordlist);
        byte[] seed = Bip39MnemonicCode.toSeed(wordlist, "TREZOR");

        Assertions.assertEquals("628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac", Utils.bytesToHex(seed));
    }

    @Test
    public void invalidBip85WordsRejected() throws MnemonicException {
        DeterministicSeed parentSeed = new DeterministicSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", 0, DeterministicSeed.Type.BIP39);
        DeterministicKey parentMasterKey = HDKeyDerivation.createMasterPrivateKey(parentSeed.getSeedBytes());
        Assertions.assertThrows(IllegalArgumentException.class, () -> Bip85.deriveBip39Child(parentMasterKey, 13, 0, 0));
    }

    @Test
    public void negativeBip85IndexRejected() throws MnemonicException {
        DeterministicSeed parentSeed = new DeterministicSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", 0, DeterministicSeed.Type.BIP39);
        DeterministicKey parentMasterKey = HDKeyDerivation.createMasterPrivateKey(parentSeed.getSeedBytes());
        Assertions.assertThrows(IllegalArgumentException.class, () -> Bip85.deriveBip39Child(parentMasterKey, 12, -1, 0));
    }

    @Test
    public void nullBip85ParentMasterKeyRejected() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> Bip85.deriveBip39Child(null, 12, 0, 0));
    }

    @Test
    public void bip85DerivesExpectedChildMnemonic() throws MnemonicException {
        DeterministicSeed parentSeed = new DeterministicSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", 0, DeterministicSeed.Type.BIP39);
        DeterministicKey parentMasterKey = HDKeyDerivation.createMasterPrivateKey(parentSeed.getSeedBytes());
        DeterministicSeed firstChild = Bip85.deriveBip39Child(parentMasterKey, 12, 0, 0);
        DeterministicSeed secondChild = Bip85.deriveBip39Child(parentMasterKey, 12, 1, 0);

        Assertions.assertEquals(DeterministicSeed.Type.BIP39, firstChild.getType());
        Assertions.assertFalse(firstChild.needsPassphrase());
        Assertions.assertEquals("prosper short ramp prepare exchange stove life snack client enough purpose fold", firstChild.getMnemonicString().asString());
        Assertions.assertEquals("sing slogan bar group gauge sphere rescue fossil loyal vital model desert", secondChild.getMnemonicString().asString());
    }

    @Test
    public void bip85MatchesPublishedBip39Vectors() throws MnemonicException {
        ExtendedKey rootXprv = ExtendedKey.fromDescriptor("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb", true);

        DeterministicSeed twelveWords = Bip85.deriveBip39Child(rootXprv.getKey(), 12, 0, 0);
        DeterministicSeed eighteenWords = Bip85.deriveBip39Child(rootXprv.getKey(), 18, 0, 0);
        DeterministicSeed twentyFourWords = Bip85.deriveBip39Child(rootXprv.getKey(), 24, 0, 0);

        Assertions.assertEquals("6250b68daf746d12a24d58b4787a714b", Utils.bytesToHex(twelveWords.getEntropyBytes()));
        Assertions.assertEquals("girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose", twelveWords.getMnemonicString().asString());
        Assertions.assertEquals("938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc", Utils.bytesToHex(eighteenWords.getEntropyBytes()));
        Assertions.assertEquals("near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token", eighteenWords.getMnemonicString().asString());
        Assertions.assertEquals("ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f", Utils.bytesToHex(twentyFourWords.getEntropyBytes()));
        Assertions.assertEquals("puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano", twentyFourWords.getMnemonicString().asString());
    }

    @Test
    public void bip85UsesParentPassphrase() throws MnemonicException {
        DeterministicSeed parentSeed = new DeterministicSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", 0, DeterministicSeed.Type.BIP39);
        DeterministicKey parentMasterKey = HDKeyDerivation.createMasterPrivateKey(parentSeed.getSeedBytes());
        DeterministicSeed parentSeedWithPassphrase = new DeterministicSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "TREZOR", 0, DeterministicSeed.Type.BIP39);
        byte[] passphrasedParentSeedBytes = parentSeedWithPassphrase.getSeedBytes();
        DeterministicKey parentMasterKeyWithPassphrase = HDKeyDerivation.createMasterPrivateKey(passphrasedParentSeedBytes);
        List<String> unpassphrasedChild = Bip85.deriveBip39Child(parentMasterKey, 12, 0, 0).getMnemonicCode();
        List<String> passphrasedChild = Bip85.deriveBip39Child(parentMasterKeyWithPassphrase, 12, 0, 0).getMnemonicCode();

        Assertions.assertEquals("prosper short ramp prepare exchange stove life snack client enough purpose fold", String.join(" ", unpassphrasedChild));
        Assertions.assertEquals("climb typical because giraffe beach wool fit ship common chapter hotel arm", String.join(" ", passphrasedChild));
        Assertions.assertNotEquals(unpassphrasedChild, passphrasedChild);
    }

    @Test
    public void allSupportedBip85WordCountsProduceValidBip39Mnemonics() throws MnemonicException {
        DeterministicSeed parentSeed = new DeterministicSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", 0, DeterministicSeed.Type.BIP39);
        DeterministicKey parentMasterKey = HDKeyDerivation.createMasterPrivateKey(parentSeed.getSeedBytes());
        for(int words : List.of(12, 15, 18, 21, 24)) {
            List<String> childMnemonic = Bip85.deriveBip39Child(parentMasterKey, words, 0, 0).getMnemonicCode();
            Assertions.assertEquals(words, childMnemonic.size());
            Bip39MnemonicCode.INSTANCE.check(childMnemonic);
        }

        Assertions.assertEquals("fruit chest ozone danger skirt worth regret atom dish figure party crater unaware armor insect", Bip85.deriveBip39Child(parentMasterKey, 15, 0, 0).getMnemonicString().asString());
        Assertions.assertEquals("produce guess spy course diesel weasel iron issue ozone sound alcohol glass huge dad because word vanish fit young color champion", Bip85.deriveBip39Child(parentMasterKey, 21, 0, 0).getMnemonicString().asString());
    }

    @Test
    public void bip85DerivedChildSeedProducesExpectedWalletKeystores() throws MnemonicException {
        DeterministicSeed parentSeed = new DeterministicSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", 0, DeterministicSeed.Type.BIP39);
        DeterministicKey parentMasterKey = HDKeyDerivation.createMasterPrivateKey(parentSeed.getSeedBytes());
        DeterministicSeed childSeed = Bip85.deriveBip39Child(parentMasterKey, 12, 0, 0);

        Keystore p2wpkhKeystore = Keystore.fromSeed(childSeed, PolicyType.SINGLE_HD, ScriptType.P2WPKH.getDefaultDerivation());
        Keystore p2trKeystore = Keystore.fromSeed(childSeed, PolicyType.SINGLE_HD, ScriptType.P2TR.getDefaultDerivation());

        Assertions.assertEquals("xprv9s21ZrQH143K2WsKAKjxbcpwauNXbTPhwMK3idULUZKUF9KBKu3bLGYXSBBytH2AGUvB93uVqSm2w9E53j7fUvzXfWLfBaqKZYbxY4okA6y", p2wpkhKeystore.getExtendedMasterPrivateKey().toString());
        Assertions.assertEquals("02e8bff2", p2wpkhKeystore.getKeyDerivation().getMasterFingerprint());
        Assertions.assertEquals("m/84'/0'/0'", p2wpkhKeystore.getKeyDerivation().getDerivationPath());
        Assertions.assertEquals("xpub6C3ABzRgTzxLdfwBA9phiSKpvx6aV251txaGgBVCinxBoCdF1ec5L8AgpbAQ1zH2zfgsGQ5GFoJ1L6jZNNLtmpSUasKEVuFrbgdJAYacaEp", p2wpkhKeystore.getExtendedPublicKey().toString());

        Assertions.assertEquals("02e8bff2", p2trKeystore.getKeyDerivation().getMasterFingerprint());
        Assertions.assertEquals("m/86'/0'/0'", p2trKeystore.getKeyDerivation().getDerivationPath());
        Assertions.assertEquals("xpub6DLdFKeBhjghPHuf3WXbEgTp6x6bi8mmzpQFf7JfKfbQ81DShYYHis74wt5rbdjxFUxKQ2o7zkkQfi2VoUkqRqEB6Z8r9WsQ5HPumjrFFBf", p2trKeystore.getExtendedPublicKey().toString());
    }

    @Test
    public void maxBip85ChildIndexAccepted() throws MnemonicException {
        DeterministicSeed parentSeed = new DeterministicSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", 0, DeterministicSeed.Type.BIP39);
        DeterministicKey parentMasterKey = HDKeyDerivation.createMasterPrivateKey(parentSeed.getSeedBytes());
        List<String> childMnemonic = Bip85.deriveBip39Child(parentMasterKey, 12, Integer.MAX_VALUE, 0).getMnemonicCode();

        Assertions.assertEquals(12, childMnemonic.size());
        Bip39MnemonicCode.INSTANCE.check(childMnemonic);
    }
}
