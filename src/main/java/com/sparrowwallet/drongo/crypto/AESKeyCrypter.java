package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.AlgorithmParameterSpec;

public class AESKeyCrypter implements KeyCrypter {

    @Override
    public EncryptionType getUnderstoodEncryptionType() {
        return null;
    }

    @Override
    public KeyParameter deriveKey(CharSequence password) throws KeyCrypterException {
        return createKeyPbkdf2HmacSha512(password.toString());
    }

    public static KeyParameter createKeyPbkdf2HmacSha512(String password) {
        return createKeyPbkdf2HmacSha512(password, new byte[0], 1024);
    }

    public static KeyParameter createKeyPbkdf2HmacSha512(String password, byte[] salt, int iterationCount) {
        byte[] secret = Utils.getPbkdf2HmacSha512Hash(password.getBytes(StandardCharsets.UTF_8), salt, iterationCount);
        return new KeyParameter(secret);
    }

    @Override
    public byte[] decrypt(EncryptedData encryptedBytesToDecode, KeyParameter aesKey) throws KeyCrypterException {
        return decryptAesCbcPkcs7(encryptedBytesToDecode.getEncryptedBytes(), encryptedBytesToDecode.getInitialisationVector(), aesKey.getKey());
    }

    private byte[] decryptAesCbcPkcs7(byte[] ciphertext, byte[] iv, byte[] key_e) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key_e, "AES");
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, paramSpec);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new KeyCrypterException("Error decrypting", e);
        }
    }

    @Override
    public EncryptedData encrypt(byte[] plainBytes, byte[] initializationVector, KeyParameter aesKey) throws KeyCrypterException {
        byte[] encryptedData = encryptAesCbcPkcs7(plainBytes, initializationVector, aesKey.getKey());
        return new EncryptedData(initializationVector, encryptedData);
    }

    private byte[] encryptAesCbcPkcs7(byte[] message, byte[] iv, byte[] key_e) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key_e, "AES");
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, paramSpec);
            return cipher.doFinal(message);
        } catch(Exception e) {
            throw new KeyCrypterException("Could not encrypt", e);
        }
    }
}
