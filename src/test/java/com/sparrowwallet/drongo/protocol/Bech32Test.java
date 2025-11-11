package com.sparrowwallet.drongo.protocol;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

public class Bech32Test {
    @Test
    public void testValidBech32Strings() {
        List<String> validStrings = Arrays.asList(
                "A12UEL5L",
                "a12uel5l",
                "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
                "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
                "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
                "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
                "?1ezyfcl"
        );
        for (String valid : validStrings) {
            Bech32.Bech32Data res = Bech32.decode(valid);
            Assertions.assertEquals(Bech32.Encoding.BECH32, res.encoding);
        }
    }

    @Test
    public void testValidBech32mStrings() {
        List<String> validStrings = Arrays.asList(
                "A1LQFN3A",
                "a1lqfn3a",
                "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
                "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
                "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
                "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
                "?1v759aa"
        );
        for (String valid : validStrings) {
            Bech32.Bech32Data res = Bech32.decode(valid);
            Assertions.assertEquals(Bech32.Encoding.BECH32M, res.encoding);
        }
    }

    @Test
    public void testHRPCharOutOfRange1() {
        char prefix = 0x20;
        String invalidBech32 = prefix + "1nwldj5";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m = prefix + "1xj0phk";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m));
    }

    @Test
    public void testHRPCharOutOfRange2() {
        char prefix = 0x7F;
        String invalidBech32 = prefix + "1axkwrx";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m = prefix + "1g6xzxy";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m));
    }

    @Test
    public void testHRPCharOutOfRange3() {
        char prefix = 0x80;
        String invalidBech32 = prefix + "1eym55h";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m = prefix + "1vctc34";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m));
    }

    @Test
    public void testOverallLengthExceeded() {
        String invalidBech32 = "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m = "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m));
    }

    @Test
    public void testNoSeparatorCharacter() {
        String invalidBech32 = "pzry9x0s0muk";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m = "qyrz8wqd2c9m";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m));
    }

    @Test
    public void testEmptyHRP() {
        String invalidBech32 = "1pzry9x0s0muk";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m = "1qyrz8wqd2c9m";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m));
    }

    @Test
    public void testInvalidBech32DataCharacter() {
        String invalidBech32 = "x1b4n0q5v";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m1 = "y1b0jsk6g";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m1));
        String invalidBech32m2 = "lt1igcx5c0";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m2));
    }

    @Test
    public void testTooShortChecksum() {
        String invalidBech32 = "li1dgmt3";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m = "in1muywd";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m));
    }

    @Test
    public void testInvalidBech32CharacterInChecksum() {
        char postfix = 0xFF;
        String invalidBech32 = "de1lg7wt" + postfix;
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m1 = "mm1crxm3i";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m1));
        String invalidBech32m2 = "au1s5cgom";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m2));
    }

    @Test
    public void testChecksumCalculatedWithUppercaseFormOfHRP() {
        String invalidBech32 = "A1G7SGD8";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m = "M1VUXWEZ";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m));
    }

    @Test
    public void testEmptyHRP1() {
        String invalidBech32 = "10a06t8";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m = "16plkw9";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m));
    }

    @Test
    public void testEmptyHRP2() {
        String invalidBech32 = "1qzzfhee";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32));
        String invalidBech32m = "1p2gdwpf";
        Assertions.assertThrows(ProtocolException.class, () -> Bech32.decode(invalidBech32m));
    }
}
