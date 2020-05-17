package com.sparrowwallet.drongo.crypto;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Helper;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Argon2KeyDeriverTest {
    @Test
    public void testArgon2() {
        String password = "thisisapassword";

        Argon2KeyDeriver keyDeriver = new Argon2KeyDeriver();
        Key key = keyDeriver.deriveKey(password);

        KeyCrypter keyCrypter = new AESKeyCrypter();

        String message = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        EncryptedData encrypted = keyCrypter.encrypt(messageBytes, iv, key);

        //Decrypt

        Argon2KeyDeriver keyDeriver2 = new Argon2KeyDeriver(encrypted.getKeySalt());
        Key key2 = keyDeriver2.deriveKey(password);

        byte[] decrypted = keyCrypter.decrypt(encrypted, key2);
        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);

        Assert.assertEquals(message, decryptedMessage);
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
