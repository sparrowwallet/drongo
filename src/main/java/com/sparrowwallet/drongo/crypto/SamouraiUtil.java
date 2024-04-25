package com.sparrowwallet.drongo.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO10126d2Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

@SuppressWarnings("deprecated")
public class SamouraiUtil {
    public static final int DefaultPBKDF2Iterations = 5000;
    public static final int DefaultPBKDF2HMACSHA256Iterations = 15000;

    public static final int MODE_CBC = 0;

    private static byte[] copyOfRange(byte[] source, int from, int to) {
        byte[] range = new byte[to - from];
        System.arraycopy(source, from, range, 0, range.length);
        return range;
    }

    // AES 256 PBKDF2 CBC iso10126 decryption
    // 16 byte IV must be prepended to ciphertext - Compatible with crypto-js

    public static String decrypt(String ciphertext, String password) throws UnsupportedEncodingException {
        return decrypt(ciphertext, password, DefaultPBKDF2Iterations);
    }

    @Deprecated
    public static String decrypt(String ciphertext, String password, int iterations) throws UnsupportedEncodingException {
        return decryptWithSetMode(ciphertext, password, iterations, MODE_CBC, new ISO10126d2Padding());
    }

    @Deprecated
    public static String decryptWithSetMode(String ciphertext, String password, int iterations, int mode, BlockCipherPadding padding) throws UnsupportedEncodingException {
        final int AESBlockSize = 4;

        byte[] cipherdata = Base64.getDecoder().decode(ciphertext.getBytes());

        //Separate the IV and cipher data
        byte[] iv = copyOfRange(cipherdata, 0, AESBlockSize * 4);
        byte[] input = copyOfRange(cipherdata, AESBlockSize * 4, cipherdata.length);

        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
        generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()), iv, iterations);
        KeyParameter keyParam = (KeyParameter) generator.generateDerivedParameters(256);

        CipherParameters params = new ParametersWithIV(keyParam, iv);

        BlockCipher cipherMode;
        if (mode == MODE_CBC) {
            cipherMode = new CBCBlockCipher(new AESEngine());

        } else {
            //mode == MODE_OFB
            cipherMode = new OFBBlockCipher(new AESEngine(), 128);
        }

        org.bouncycastle.crypto.BufferedBlockCipher cipher;
        if (padding != null) {
            cipher = new PaddedBufferedBlockCipher(cipherMode, padding);
        } else {
            cipher = new BufferedBlockCipher(cipherMode);
        }

        cipher.reset();
        cipher.init(false, params);

        // create a temporary buffer to decode into (includes padding)
        byte[] buf = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.processBytes(input, 0, input.length, buf, 0);
        try {
            len += cipher.doFinal(buf, len);
        } catch(InvalidCipherTextException e) {
            throw new UnsupportedEncodingException(e.getMessage());
        }

        // remove padding
        byte[] out = new byte[len];
        System.arraycopy(buf, 0, out, 0, len);

        // return string representation of decoded bytes
        String result = new String(out, StandardCharsets.UTF_8);
        if (result.isEmpty()) {
            throw new IllegalArgumentException("Decrypted string is empty.");
        }

        return result;
    }

    public static String decryptSHA256(String ciphertext, String password) throws BadPaddingException, CharacterCodingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        return decryptSHA256(ciphertext, password, DefaultPBKDF2HMACSHA256Iterations);
    }

    public static String decryptSHA256(String ciphertext, String password, int iterations) throws BadPaddingException, CharacterCodingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        return decrypt_AES256CBC_PBKDF2_HMAC_SHA256(password, iterations, ciphertext);
    }

    private static String decrypt_AES256CBC_PBKDF2_HMAC_SHA256(String password, int hashIterations, String stringToDecrypt)
            throws BadPaddingException, CharacterCodingException,
            IllegalArgumentException, IllegalBlockSizeException, IndexOutOfBoundsException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException {

        byte[] encryptedBytes = Base64.getDecoder().decode(stringToDecrypt.replaceAll("\\s+", ""));

        // Salt is bytes 8 - 15
        byte[] salt = new byte[8];
        System.arraycopy(encryptedBytes, 8, salt, 0, 8);

        // Derive 48 byte key
        SecretKeySpecAndIv components = getSecretKeyComponents(password, salt, hashIterations);

        // Cipher Text is bytes 16 - end of the encrypted bytes
        byte[] cipherText = new byte[encryptedBytes.length - 16];
        System.arraycopy(encryptedBytes, 16, cipherText, 0, encryptedBytes.length - 16);

        // Decrypt the Cipher Text and manually remove padding after
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, components.getSecretKeySpec(), components.getIvParameterSpec());
        byte[] decrypted = cipher.doFinal(cipherText);

        if(!isValidUTF8(decrypted)) {
            throw new CharacterCodingException();
        }

        // Last byte of the decrypted text is the number of padding bytes needed to remove
        byte[] plaintext = new byte[decrypted.length - decrypted[decrypted.length - 1]];
        System.arraycopy(decrypted, 0, plaintext, 0, plaintext.length);

        return new String(plaintext, java.nio.charset.StandardCharsets.UTF_8).trim();
    }

    private static SecretKeySpecAndIv getSecretKeyComponents(String password, byte[] salt, int hashIterations) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(password.getBytes(), salt, hashIterations);
        KeyParameter secretKey = (KeyParameter) generator.generateDerivedMacParameters(48 * 8);

        byte[] key = Arrays.copyOfRange(secretKey.getKey(), 0, 32);
        byte[] iv = Arrays.copyOfRange(secretKey.getKey(), 32, secretKey.getKey().length);

        Arrays.fill(generator.getPassword(), (byte)'*');
        Arrays.fill(secretKey.getKey(), (byte)'*');

        return new SecretKeySpecAndIv(new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    }

    private static boolean isValidUTF8(byte[] input) {
        try {
            StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(input));
            return true;
        } catch (CharacterCodingException e) {
            return false;
        }
    }

    private static class SecretKeySpecAndIv {
        private final SecretKeySpec key;
        private final IvParameterSpec iv;

        SecretKeySpecAndIv(SecretKeySpec key, IvParameterSpec iv) {
            this.key = key;
            this.iv = iv;
        }

        public SecretKeySpec getSecretKeySpec() {
            return key;
        }

        public IvParameterSpec getIvParameterSpec() {
            return iv;
        }
    }
}
