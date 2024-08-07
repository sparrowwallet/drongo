package com.sparrowwallet.drongo.wallet.slip39;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static com.sparrowwallet.drongo.wallet.slip39.Share.*;
import static com.sparrowwallet.drongo.wallet.slip39.Utils.concatenate;

public class Cipher {
    public static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for(int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    public static byte[] roundFunction(int i, byte[] passphrase, int e, byte[] salt, byte[] r) {
        int iterations = (BASE_ITERATION_COUNT << e) / ROUND_COUNT;
        byte[] input = new byte[1 + passphrase.length];
        input[0] = (byte) i;
        System.arraycopy(passphrase, 0, input, 1, passphrase.length);

        try {
            PBEKeySpec spec = new PBEKeySpec(new String(input, StandardCharsets.UTF_8).toCharArray(), concatenate(salt, r), iterations, r.length * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException("Error during round function", ex);
        }
    }

    public static byte[] getSalt(int identifier, boolean extendable) {
        if(extendable) {
            return new byte[0];
        }
        int identifierLen = Utils.bitsToBytes(ID_LENGTH_BITS);
        byte[] idBytes = toByteArray(identifier, identifierLen);
        return concatenate(CUSTOMIZATION_STRING_ORIG, idBytes);
    }

    public static byte[] encrypt(byte[] masterSecret, byte[] passphrase, int iterationExponent, int identifier, boolean extendable) {
        if (masterSecret.length % 2 != 0) {
            throw new IllegalArgumentException("The length of the master secret in bytes must be an even number.");
        }

        byte[] l = Arrays.copyOfRange(masterSecret, 0, masterSecret.length / 2);
        byte[] r = Arrays.copyOfRange(masterSecret, masterSecret.length / 2, masterSecret.length);
        byte[] salt = getSalt(identifier, extendable);

        for (int i = 0; i < ROUND_COUNT; i++) {
            byte[] f = roundFunction(i, passphrase, iterationExponent, salt, r);
            byte[] newR = xor(l, f);
            l = r;
            r = newR;
        }

        return concatenate(r, l);
    }

    public static byte[] decrypt(byte[] encryptedMasterSecret, byte[] passphrase, int iterationExponent, int identifier, boolean extendable) {
        if (encryptedMasterSecret.length % 2 != 0) {
            throw new IllegalArgumentException("The length of the encrypted master secret in bytes must be an even number.");
        }

        byte[] l = Arrays.copyOfRange(encryptedMasterSecret, 0, encryptedMasterSecret.length / 2);
        byte[] r = Arrays.copyOfRange(encryptedMasterSecret, encryptedMasterSecret.length / 2, encryptedMasterSecret.length);
        byte[] salt = getSalt(identifier, extendable);

        for (int i = ROUND_COUNT - 1; i >= 0; i--) {
            byte[] f = roundFunction(i, passphrase, iterationExponent, salt, r);
            byte[] newR = xor(l, f);
            l = r;
            r = newR;
        }

        return concatenate(r, l);
    }

    private static byte[] toByteArray(int value, int length) {
        byte[] result = new byte[length];
        for (int i = length - 1; i >= 0; i--) {
            result[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return result;
    }
}
