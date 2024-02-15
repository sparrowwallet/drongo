package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;
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
}