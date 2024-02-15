package com.sparrowwallet.drongo.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class ScryptKeyDeriverTest {
    @Test
    public void testScrypt() {
        ScryptKeyDeriver scryptKeyDeriver = new ScryptKeyDeriver();
        Key key = scryptKeyDeriver.deriveKey("pass");

        KeyCrypter keyCrypter = new AESKeyCrypter();

        String message = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        EncryptedData scrypted = keyCrypter.encrypt(messageBytes, iv, key);

        //Decrypt

        ScryptKeyDeriver scryptKeyDeriver2 = new ScryptKeyDeriver(scrypted.getKeySalt());
        Key key2 = scryptKeyDeriver2.deriveKey("pass");

        byte[] sdecrypted = keyCrypter.decrypt(scrypted, key2);
        String decryptedMessage = new String(sdecrypted, StandardCharsets.UTF_8);

        Assertions.assertEquals(message, decryptedMessage);
    }
}
