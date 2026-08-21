package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.protocol.Base58;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class BIP38Test {
    @Test
    public void testNoCompressionNoEC() throws GeneralSecurityException, UnsupportedEncodingException {
        Assertions.assertEquals("5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR", BIP38.decrypt("TestingOneTwoThree", "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg").toString()); ;
        Assertions.assertEquals("5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5", BIP38.decrypt("Satoshi", "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq").toString()); ;
    }

    @Test
    public void testCompressionNoEC() throws GeneralSecurityException, UnsupportedEncodingException {
        Assertions.assertEquals("L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP", BIP38.decrypt("TestingOneTwoThree", "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo").toString()); ;
        Assertions.assertEquals("KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7", BIP38.decrypt("Satoshi", "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7").toString()); ;
    }

    @Test
    public void testCompressionEC() throws GeneralSecurityException, UnsupportedEncodingException {
        Assertions.assertEquals("5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2", BIP38.decrypt("TestingOneTwoThree", "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX").toString()); ;
        Assertions.assertEquals("5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH", BIP38.decrypt("Satoshi", "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd").toString()); ;
    }

    @Test
    public void testCompressionECLot() throws GeneralSecurityException, UnsupportedEncodingException {
        Assertions.assertEquals("5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8", BIP38.decrypt("MOLON LABE", "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j").toString()); ;
        Assertions.assertEquals("5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D", BIP38.decrypt("ΜΟΛΩΝ ΛΑΒΕ", "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH").toString()); ;
    }

    @Test
    public void testCompressionFlagEC() throws GeneralSecurityException, UnsupportedEncodingException {
        //BIP38 provides no EC multiply vector with the compression flag set. Both of these were generated from the same passphrase, owner salt and seedb,
        //differing only in the flag byte - the uncompressed one is included because it can be checked against the vectors above.
        Assertions.assertEquals("5KQQSnRzBAXc5eehc6Q1mQGxghSFLS1H1pChoqP4LtPoKrkWzkz", BIP38.decrypt("TestingOneTwoThree", "6PfT3aPZr59YLHDHVz6yem2FuvXsUdDEPNYw7ArG11BFdpG31SqC9f9eUn").toString());
        Assertions.assertEquals("L4EJUoXHMs45qXBQDtpaNyjSnDUSGmNDgbLf7iYMkmqdUDybFMfN", BIP38.decrypt("TestingOneTwoThree", "6PnRe5H6XHsMpnJyHtJNKQ8MtGBQhTwNqQpdHKwKLYWsZogTGQ1SiL39A7").toString());
    }

    @Test
    public void testIncorrectPassphrase() {
        Assertions.assertThrows(InvalidPasswordException.class, () -> BIP38.decrypt("TestingOneTwoThreeFour", "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"));
        Assertions.assertThrows(InvalidPasswordException.class, () -> BIP38.decrypt("TestingOneTwoThreeFour", "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo"));
        Assertions.assertThrows(InvalidPasswordException.class, () -> BIP38.decrypt("TestingOneTwoThreeFour", "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX"));
        Assertions.assertThrows(InvalidPasswordException.class, () -> BIP38.decrypt("MOLON LABE!", "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j"));
    }

    @Test
    public void testMalformedKey() {
        byte[] valid = Base58.decodeChecked("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg");
        byte[] truncated = Arrays.copyOfRange(valid, 0, valid.length - 1);
        byte[] unknownType = Arrays.copyOf(valid, valid.length);
        unknownType[1] = 0x44;

        Assertions.assertThrows(GeneralSecurityException.class, () -> BIP38.decrypt("TestingOneTwoThree", Base58.encodeChecked(truncated)));
        Assertions.assertThrows(GeneralSecurityException.class, () -> BIP38.decrypt("TestingOneTwoThree", Base58.encodeChecked(unknownType)));
        Assertions.assertThrows(GeneralSecurityException.class, () -> BIP38.decryptNoEC("TestingOneTwoThree", truncated));
        Assertions.assertThrows(GeneralSecurityException.class, () -> BIP38.decryptEC("TestingOneTwoThree", truncated));
    }
}
