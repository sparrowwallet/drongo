package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Argon2KeyDeriverTest {
    @Test
    public void noPasswordTest() {
        String password = "";

        Argon2KeyDeriver.Argon2Parameters testParams = Argon2KeyDeriver.TEST_PARAMETERS;
        byte[] salt = new byte[testParams.saltLength];
        Argon2KeyDeriver keyDeriver = new Argon2KeyDeriver(salt);
        Key key = keyDeriver.deriveKey(password);

        String hex = Utils.bytesToHex(key.getKeyBytes());
        Assertions.assertEquals("6f6600a054c0271b96788906f62dfb1323c37b761715a0ae95ac524e4e1f2811", hex);
    }

    @Test
    public void testArgon2() {
        String password = "thisisapassword";

        Argon2KeyDeriver keyDeriver = new Argon2KeyDeriver(Argon2KeyDeriver.TEST_PARAMETERS);
        Key key = keyDeriver.deriveKey(password);

        KeyCrypter keyCrypter = new AESKeyCrypter();

        String message = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        EncryptedData encrypted = keyCrypter.encrypt(messageBytes, iv, key);

        //Decrypt

        Argon2KeyDeriver keyDeriver2 = new Argon2KeyDeriver(Argon2KeyDeriver.TEST_PARAMETERS, encrypted.getKeySalt());
        Key key2 = keyDeriver2.deriveKey(password);

        byte[] decrypted = keyCrypter.decrypt(encrypted, key2);
        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);

        Assertions.assertEquals(message, decryptedMessage);
    }

//    @Test
//    public void findIterations() {
//        Argon2 argon2 = Argon2Factory.create();
//        // 1000 = The hash call must take at most 1000 ms
//        // 65536 = Memory cost
//        // 1 = parallelism
//        int iterations = Argon2Helper.findIterations(argon2, 500, 256*1024, 4);
//
//        System.out.println("Optimal number of iterations: " + iterations);
//    }
}
