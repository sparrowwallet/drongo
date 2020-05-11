package com.sparrowwallet.drongo.crypto;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

public class ScryptKeyCrypterTest {
    @Test
    public void testScrypt() {
        Security.addProvider(new BouncyCastleProvider());

        KeyCrypter keyDeriver = new AESKeyCrypter();
        KeyParameter keyParameter = keyDeriver.deriveKey("password");

        String message = "testastringmessage";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        ScryptKeyCrypter scryptKeyCrypter = new ScryptKeyCrypter();
        EncryptedData scrypted = scryptKeyCrypter.encrypt(messageBytes, iv, keyParameter);

        AESKeyCrypter aesKeyCrypter = new AESKeyCrypter();
        EncryptedData aescrypted = aesKeyCrypter.encrypt(messageBytes, iv, keyParameter);

        Assert.assertArrayEquals(scrypted.getEncryptedBytes(), aescrypted.getEncryptedBytes());

        byte[] sdecrypted = scryptKeyCrypter.decrypt(scrypted, keyParameter);
        byte[] aesdecrypted = aesKeyCrypter.decrypt(aescrypted, keyParameter);

        Assert.assertArrayEquals(sdecrypted, aesdecrypted);
    }
}
