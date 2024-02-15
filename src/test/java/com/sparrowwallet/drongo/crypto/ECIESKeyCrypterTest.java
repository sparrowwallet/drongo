package com.sparrowwallet.drongo.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

public class ECIESKeyCrypterTest {
    @Test
    public void encryptDecrypt() {
        String testMessage = "thisisatestmessage";
        byte[] testMessageBytes = testMessage.getBytes(StandardCharsets.UTF_8);
        byte[] initializationVector = "BIE1".getBytes(StandardCharsets.UTF_8);

        AsymmetricKeyDeriver keyDeriver = new Pbkdf2KeyDeriver();
        ECKey key = keyDeriver.deriveECKey("iampassword");

        AsymmetricKeyCrypter keyCrypter = new ECIESKeyCrypter();
        EncryptedData encryptedData = keyCrypter.encrypt(testMessageBytes, initializationVector, key);
        byte[] crypterDecrypted = keyCrypter.decrypt(encryptedData, key);

        String cryDecStr = new String(crypterDecrypted, StandardCharsets.UTF_8);
        Assertions.assertEquals(testMessage, cryDecStr);
    }
}
