package com.sparrowwallet.drongo.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

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
}
