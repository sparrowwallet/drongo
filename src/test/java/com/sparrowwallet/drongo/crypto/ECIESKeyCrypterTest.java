package com.sparrowwallet.drongo.crypto;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class ECIESKeyCrypterTest {
    @Test
    public void encryptDecrypt() {
        String testMessage = "thisisatestmessage";
        byte[] testMessageBytes = testMessage.getBytes(StandardCharsets.UTF_8);
        byte[] initializationVector = "BIE1".getBytes(StandardCharsets.UTF_8);

        AsymmetricKeyCrypter keyCrypter = new ECIESKeyCrypter();

        ECKey key = keyCrypter.deriveECKey("iampassword");
        EncryptedData encryptedData = keyCrypter.encrypt(testMessageBytes, initializationVector, key);
        byte[] crypterDecrypted = keyCrypter.decrypt(encryptedData, key);

        String cryDecStr = new String(crypterDecrypted, StandardCharsets.UTF_8);
        Assert.assertEquals(testMessage, cryDecStr);
    }
}
