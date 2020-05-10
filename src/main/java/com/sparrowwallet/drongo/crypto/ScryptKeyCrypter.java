package com.sparrowwallet.drongo.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * <p>This class encrypts and decrypts byte arrays and strings using scrypt as the
 * key derivation function and AES for the encryption.</p>
 *
 * <p>You can use this class to:</p>
 *
 * <p>1) Using a user password, create an AES key that can encrypt and decrypt your private keys.
 * To convert the password to the AES key, scrypt is used. This is an algorithm resistant
 * to brute force attacks. You can use the ScryptParameters to tune how difficult you
 * want this to be generation to be.</p>
 *
 * <p>2) Using the AES Key generated above, you then can encrypt and decrypt any bytes using
 * the AES symmetric cipher. Eight bytes of salt is used to prevent dictionary attacks.</p>
 */
public class ScryptKeyCrypter implements KeyCrypter {
    private static final Logger log = LoggerFactory.getLogger(ScryptKeyCrypter.class);

    /**
     * Key length in bytes.
     */
    public static final int KEY_LENGTH = 32; // = 256 bits.

    /**
     * The size of an AES block in bytes.
     * This is also the length of the initialisation vector.
     */
    public static final int BLOCK_LENGTH = 16;  // = 128 bits.

    /**
     * The length of the salt used.
     */
    public static final int SALT_LENGTH = 8;

    private static final SecureRandom secureRandom = new SecureRandom();

    /** Returns SALT_LENGTH (8) bytes of random data */
    public static byte[] randomSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    // Scrypt parameters.
    private final ScryptParameters scryptParameters;

    /**
     * Encryption/Decryption using default parameters and a random salt.
     */
    public ScryptKeyCrypter() {
        this.scryptParameters = new ScryptParameters(randomSalt());
    }

    /**
     * Encryption/Decryption using custom number of iterations parameters and a random salt.
     * As of August 2016, a useful value for mobile devices is 4096 (derivation takes about 1 second).
     *
     * @param iterations
     *            number of scrypt iterations
     */
    public ScryptKeyCrypter(int iterations) {
        this.scryptParameters = new ScryptParameters(randomSalt(), iterations);
    }

    /**
     * Encryption/ Decryption using specified Scrypt parameters.
     *
     * @param scryptParameters ScryptParameters to use
     * @throws NullPointerException if the scryptParameters or any of its N, R or P is null.
     */
    public ScryptKeyCrypter(ScryptParameters scryptParameters) {
        this.scryptParameters = scryptParameters;
        if (scryptParameters.getSalt() == null || scryptParameters.getSalt() == null || scryptParameters.getSalt().length == 0) {
            log.warn("You are using a ScryptParameters with no salt. Your encryption may be vulnerable to a dictionary attack.");
        }
    }

    /**
     * Generate AES key.
     *
     * This is a very slow operation compared to encrypt/ decrypt so it is normally worth caching the result.
     *
     * @param password    The password to use in key generation
     * @return            The KeyParameter containing the created AES key
     * @throws            KeyCrypterException
     */
    @Override
    public KeyParameter deriveKey(CharSequence password) throws KeyCrypterException {
        byte[] passwordBytes = null;
        try {
            passwordBytes = convertToByteArray(password);
            byte[] salt = new byte[0];
            if (scryptParameters.getSalt() != null) {
                salt = scryptParameters.getSalt();
            } else {
                log.warn("You are using a ScryptParameters with no salt. Your encryption may be vulnerable to a dictionary attack.");
            }

            byte[] keyBytes = SCrypt.generate(passwordBytes, salt, (int) scryptParameters.getN(), scryptParameters.getR(), scryptParameters.getP(), KEY_LENGTH);
            return new KeyParameter(keyBytes);
        } catch (Exception e) {
            throw new KeyCrypterException("Could not generate key from password and salt.", e);
        } finally {
            // Zero the password bytes.
            if(passwordBytes != null) {
                java.util.Arrays.fill(passwordBytes, (byte) 0);
            }
        }
    }

    /**
     * Password based encryption using AES - CBC 256 bits.
     */
    @Override
    public EncryptedData encrypt(byte[] plainBytes, byte[] initializationVector, KeyParameter aesKey) throws KeyCrypterException {
        if(plainBytes == null || aesKey == null) {
            throw new KeyCrypterException("Data and key to encrypt cannot be null");
        }

        try {
            // Generate iv - each encryption call has a different iv.
            byte[] iv = initializationVector;
            if(iv == null) {
                iv = new byte[BLOCK_LENGTH];
                secureRandom.nextBytes(iv);
            }

            ParametersWithIV keyWithIv = new ParametersWithIV(aesKey, iv);

            // Encrypt using AES.
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            cipher.init(true, keyWithIv);
            byte[] encryptedBytes = new byte[cipher.getOutputSize(plainBytes.length)];
            final int length1 = cipher.processBytes(plainBytes, 0, plainBytes.length, encryptedBytes, 0);
            final int length2 = cipher.doFinal(encryptedBytes, length1);

            return new EncryptedData(iv, Arrays.copyOf(encryptedBytes, length1 + length2));
        } catch (Exception e) {
            throw new KeyCrypterException("Could not encrypt bytes.", e);
        }
    }

    /**
     * Decrypt bytes previously encrypted with this class.
     *
     * @param dataToDecrypt    The data to decrypt
     * @param aesKey           The AES key to use for decryption
     * @return                 The decrypted bytes
     * @throws                 KeyCrypterException if bytes could not be decrypted
     */
    @Override
    public byte[] decrypt(EncryptedData dataToDecrypt, KeyParameter aesKey) throws KeyCrypterException {
        if(dataToDecrypt == null || aesKey == null) {
            throw new KeyCrypterException("Data and key to decrypt cannot be null");
        }

        try {
            ParametersWithIV keyWithIv = new ParametersWithIV(new KeyParameter(aesKey.getKey()), dataToDecrypt.getInitialisationVector());

            // Decrypt the message.
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            cipher.init(false, keyWithIv);

            byte[] cipherBytes = dataToDecrypt.getEncryptedBytes();
            byte[] decryptedBytes = new byte[cipher.getOutputSize(cipherBytes.length)];
            final int length1 = cipher.processBytes(cipherBytes, 0, cipherBytes.length, decryptedBytes, 0);
            final int length2 = cipher.doFinal(decryptedBytes, length1);

            return Arrays.copyOf(decryptedBytes, length1 + length2);
        } catch (InvalidCipherTextException e) {
            throw new KeyCrypterException.InvalidCipherText("Could not decrypt bytes", e);
        } catch (RuntimeException e) {
            throw new KeyCrypterException("Could not decrypt bytes", e);
        }
    }

    /**
     * Convert a CharSequence (which are UTF16) into a byte array.
     *
     * Note: a String.getBytes() is not used to avoid creating a String of the password in the JVM.
     */
    private static byte[] convertToByteArray(CharSequence charSequence) {
        byte[] byteArray = new byte[charSequence.length() << 1];
        for(int i = 0; i < charSequence.length(); i++) {
            int bytePosition = i << 1;
            byteArray[bytePosition] = (byte) ((charSequence.charAt(i)&0xFF00)>>8);
            byteArray[bytePosition + 1] = (byte) (charSequence.charAt(i)&0x00FF);
        }
        return byteArray;
    }

    public ScryptParameters getScryptParameters() {
        return scryptParameters;
    }

    /**
     * Return the EncryptionType enum value which denotes the type of encryption/ decryption that this KeyCrypter
     * can understand.
     */
    @Override
    public EncryptionType getUnderstoodEncryptionType() {
        return EncryptionType.ENCRYPTED_SCRYPT_AES;
    }

    @Override
    public String toString() {
        return "AES-" + KEY_LENGTH * 8 + "-CBC, Scrypt (" + scryptParametersString() + ")";
    }

    private String scryptParametersString() {
        return "N=" + scryptParameters.getN() + ", r=" + scryptParameters.getR() + ", p=" + scryptParameters.getP();
    }

    @Override
    public int hashCode() {
        return Objects.hash(scryptParameters);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return Objects.equals(scryptParameters, ((ScryptKeyCrypter)o).scryptParameters);
    }

    public static class ScryptParameters {
        private final byte[] salt;
        private long n = 16384L;

        public ScryptParameters(byte[] salt) {
            this.salt = salt;
        }

        public ScryptParameters(byte[] salt, long iterations) {
            this.salt = salt;
            this.n = iterations;
        }

        byte[] getSalt() {
           return salt;
        }

        long getN() {
            return n;
        }

        int getR() {
            return 8;
        }

        int getP() {
            return 1;
        }
    }
}
