package com.sparrowwallet.drongo.wallet.bip93;

import com.sparrowwallet.drongo.protocol.Bech32;
import com.sparrowwallet.drongo.wallet.MnemonicException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;


public class Codex32Test {
    // Codex32 -> BIP32 secret testing, and eventually share derivations testing. xprv derivations testing lives in KeystoreTest.java

    @Test
    public void bip93TestVector1() throws MnemonicException {
        Codex32.Codex32Data data = Codex32.decode("ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw");
        Assertions.assertEquals(0, data.getThresholdAsInt());
        Assertions.assertEquals("test", data.identifierAsString());
        Assertions.assertTrue(data.isUnsharedSecret());
        Assertions.assertEquals("318c6318c6318c6318c6318c6318c631", HexFormat.of().formatHex(data.payloadToBip32Secret()));
        Assertions.assertEquals("ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw", Codex32.encode(data));
    }

    @Test
    public void bip93TestVector2() throws MnemonicException {
        Codex32.Codex32Data aShare = Codex32.decode("MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM");
        Assertions.assertEquals(2, aShare.getThresholdAsInt());
        Assertions.assertEquals("name", aShare.identifierAsString());
        Assertions.assertEquals(Bech32.CHARSET_REV['a'], aShare.getShareIndex());
        Assertions.assertFalse(aShare.isUnsharedSecret());

        Codex32.Codex32Data cShare = Codex32.decode("MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN");
        Assertions.assertEquals(2, cShare.getThresholdAsInt());
        Assertions.assertEquals("name", cShare.identifierAsString());
        Assertions.assertEquals(Bech32.CHARSET_REV['c'], cShare.getShareIndex());
        Assertions.assertFalse(cShare.isUnsharedSecret());

        // TODO: Test derivations once that's built

        Codex32.Codex32Data dShare = Codex32.decode("MS12NAMEDLL4F8JLH4E5VDVULDLFXU2JHDNLSM97XVENRXEG");
        Assertions.assertEquals(2, dShare.getThresholdAsInt());
        Assertions.assertEquals("name", dShare.identifierAsString());
        Assertions.assertEquals(Bech32.CHARSET_REV['d'], dShare.getShareIndex());
        Assertions.assertFalse(dShare.isUnsharedSecret());

        Codex32.Codex32Data data = Codex32.decode("MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW");
        Assertions.assertEquals(2, data.getThresholdAsInt());
        Assertions.assertEquals("name", data.identifierAsString());
        Assertions.assertTrue(data.isUnsharedSecret());
        Assertions.assertEquals("d1808e096b35b209ca12132b264662a5", HexFormat.of().formatHex(data.payloadToBip32Secret()));
        Assertions.assertEquals("MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW".toLowerCase(Locale.ROOT), Codex32.encode(data));
    }

    @Test
    public void bip93TestVector3() throws MnemonicException {
        Codex32.Codex32Data data = Codex32.decode("ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln");
        Assertions.assertEquals(3, data.getThresholdAsInt());
        Assertions.assertEquals("cash", data.identifierAsString());
        Assertions.assertTrue(data.isUnsharedSecret());
        Assertions.assertEquals("ffeeddccbbaa99887766554433221100", HexFormat.of().formatHex(data.payloadToBip32Secret()));
        Assertions.assertEquals("ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln", Codex32.encode(data));

        Codex32.Codex32Data aShare = Codex32.decode("ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t");
        Assertions.assertEquals(3, aShare.getThresholdAsInt());
        Assertions.assertEquals("cash", aShare.identifierAsString());
        Assertions.assertEquals(Bech32.CHARSET_REV['a'], aShare.getShareIndex());
        Assertions.assertFalse(aShare.isUnsharedSecret());
        Assertions.assertEquals("ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t", Codex32.encode(aShare));

        Codex32.Codex32Data cShare = Codex32.decode("ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr");
        Assertions.assertEquals(3, cShare.getThresholdAsInt());
        Assertions.assertEquals("cash", cShare.identifierAsString());
        Assertions.assertEquals(Bech32.CHARSET_REV['c'], cShare.getShareIndex());
        Assertions.assertFalse(cShare.isUnsharedSecret());
        Assertions.assertEquals("ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr", Codex32.encode(cShare));

        // TODO: Test derivations once that exists

        Codex32.Codex32Data dShare = Codex32.decode("ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm");
        Assertions.assertEquals(3, dShare.getThresholdAsInt());
        Assertions.assertEquals("cash", dShare.identifierAsString());
        Assertions.assertEquals(Bech32.CHARSET_REV['d'], dShare.getShareIndex());
        Assertions.assertFalse(dShare.isUnsharedSecret());
        Assertions.assertEquals("ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm", Codex32.encode(dShare));

        Codex32.Codex32Data eShare = Codex32.decode("ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9");
        Assertions.assertEquals(3, eShare.getThresholdAsInt());
        Assertions.assertEquals("cash", eShare.identifierAsString());
        Assertions.assertEquals(Bech32.CHARSET_REV['e'], eShare.getShareIndex());
        Assertions.assertFalse(eShare.isUnsharedSecret());
        Assertions.assertEquals("ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9", Codex32.encode(eShare));

        Codex32.Codex32Data fShare = Codex32.decode("ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704");
        Assertions.assertEquals(3, fShare.getThresholdAsInt());
        Assertions.assertEquals("cash", fShare.identifierAsString());
        Assertions.assertEquals(Bech32.CHARSET_REV['f'], fShare.getShareIndex());
        Assertions.assertFalse(fShare.isUnsharedSecret());
        Assertions.assertEquals("ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704", Codex32.encode(fShare));
    }

    @Test
    public void bip93TestVector4() throws MnemonicException {
        Codex32.Codex32Data data = Codex32.decode("ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma");
        Assertions.assertEquals(0, data.getThresholdAsInt());
        Assertions.assertEquals("leet", data.identifierAsString());
        Assertions.assertTrue(data.isUnsharedSecret());
        Assertions.assertEquals("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100", HexFormat.of().formatHex(data.payloadToBip32Secret()));
        Assertions.assertEquals("ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma", Codex32.encode(data));
    }

    @Test
    public void bip93TestVector5() throws MnemonicException {
        Codex32.Codex32Data data = Codex32.decode("MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK");
        Assertions.assertEquals(0, data.getThresholdAsInt());
        Assertions.assertEquals("0c8v", data.identifierAsString());
        Assertions.assertTrue(data.isUnsharedSecret());
        Assertions.assertEquals("dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9", HexFormat.of().formatHex(data.payloadToBip32Secret()));
        Assertions.assertEquals("ms100c8vsm32zxfguhpchtlupzry9x8gf2tvdw0s3jn54khce6mua7lqpzygsfjd6an074rxvcemlh8wu3tk925acdefghjklmnpqrstuvwxy06fhpv80undvarhrak", Codex32.encode(data));
    }

    @Test
    public void bip93InvalidShares() {
        // Incorrect checksums
        List<String> invalidChecksum = Arrays.asList(
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghq",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghp",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxlk3yepcstwr",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx6pgnv7jnpcsp",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxx0cpvr7n4geq",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxm5252y7d3lr",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxrd9sukzl05ej",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxc55srw5jrm0",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxgc7rwhtudwc",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx4gy22afwghvs",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxe8yfm0",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxvm597d",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pe0",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pew",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxqyadsp3nywm8a",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxzvg7ar4hgaejk",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcznau0advgxqe",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxch3jrc6j5040j",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx52gxl6ppv40mcv",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx7g4g2nhhle8fk",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx63m45uj8ss4x8",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxy4r708q7kg65x"
        );
        for(String invalid : invalidChecksum) {
            Assertions.assertThrows(MnemonicException.class, () -> Codex32.decode(invalid));
        }

        // Wrong checksum for their given data sizes
        List<String> wrongChecksumForSize = Arrays.asList(
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxurfvwmdcmymdufv",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxcsyppjkd8lz4hx3",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxu6hwvl5p0l9xf3c",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxwqey9rfs6smenxa",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxv70wkzrjr4ntqet",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx3hmlrmpa4zl0v",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxrfggf88znkaup",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpt7l4aycv9qzj",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxus27z9xtyxyw3",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcwm4re8fs78vn"
        );
        for(String invalid : wrongChecksumForSize) {
            Assertions.assertThrows(MnemonicException.class, () -> Codex32.decode(invalid));
        }

        // These examples have improper lengths. They are either too short, too long,
        // or would decode to byte sequence with an incomplete group greater than 4 bits
        List<String> improperLength = Arrays.asList(
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxw0a4c70rfefn4",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxk4pavy5n46nea",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx9lrwar5zwng4w",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxr335l5tv88js3",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxvu7q9nz8p7dj68v",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpq6k542scdxndq3",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxkmfw6jm270mz6ej",
                "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxzhddxw99w7xws",
                "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx42cux6um92rz",
                "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxarja5kqukdhy9",
                "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxky0ua3ha84qk8",
                "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9eheesxadh2n2n9",
                "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9llwmgesfulcj2z",
                "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx02ev7caq6n9fgkf"
        );
        for(String invalid : improperLength) {
            Assertions.assertThrows(MnemonicException.class, () -> Codex32.decode(invalid));
        }

        // A "0" threshold with a non-"s" index
        Assertions.assertThrows(MnemonicException.class, () -> Codex32.decode("ms10fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx0z26tfn0ulw3p"));

        // A non-digit threshold
        Assertions.assertThrows(MnemonicException.class, () -> Codex32.decode("ms1fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxda3kr3s0s2swg"));

        // Do not begin with the required "ms" or "MS" prefix and/or are missing the "1" separator
        List<String> invalidPrefix = Arrays.asList(
                "0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
                "10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
                "ms0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
                "m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
                "s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
                "0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
                "10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
                "m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxx8t28z74x8hs4l",
                "s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxh9d0fhnvfyx3x"
        );
        for(String invalid : invalidPrefix) {
            Assertions.assertThrows(MnemonicException.class, () -> Codex32.decode(invalid));
        }

        // Incorrectly mix upper and lower case characters
        List<String> caseMix = Arrays.asList(
                "Ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
                "mS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
                "MS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
                "ms10FAUXsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
                "ms10fauxSxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
                "ms10fauxsXXXXXXXXXXXXXXXXXXXXXXXXXXuqxkk05lyf3x2",
                "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxUQXKK05LYF3X2"
        );
        for(String invalid : caseMix) {
            Assertions.assertThrows(MnemonicException.class, () -> Codex32.decode(invalid));
        }
    }
}
