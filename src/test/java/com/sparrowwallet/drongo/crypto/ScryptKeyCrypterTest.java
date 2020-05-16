package com.sparrowwallet.drongo.crypto;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class ScryptKeyCrypterTest {
    @Test
    public void testScrypt() {
        ScryptKeyCrypter scryptKeyCrypter = new ScryptKeyCrypter();
        Key key = scryptKeyCrypter.deriveKey("pass");

        String message = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        EncryptedData scrypted = scryptKeyCrypter.encrypt(messageBytes, iv, key);

        AESKeyCrypter aesKeyCrypter = new AESKeyCrypter();
        EncryptedData aescrypted = aesKeyCrypter.encrypt(messageBytes, iv, key);

        Assert.assertArrayEquals(scrypted.getEncryptedBytes(), aescrypted.getEncryptedBytes());

        byte[] sdecrypted = scryptKeyCrypter.decrypt(scrypted, key);
        byte[] aesdecrypted = aesKeyCrypter.decrypt(aescrypted, key);

        Assert.assertArrayEquals(sdecrypted, aesdecrypted);

        String decryptedMessage = new String(sdecrypted, StandardCharsets.UTF_8);

        Assert.assertEquals(message, decryptedMessage);
    }
}
