package com.sparrowwallet.drongo.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.security.SecureRandom;
import java.util.Arrays;

/*
 * Performs AES/CBC/PKCS7 encryption and decryption
 */
public class AESKeyCrypter implements KeyCrypter {
    /**
     * The size of an AES block in bytes.
     * This is also the length of the initialisation vector.
     */
    public static final int BLOCK_LENGTH = 16;  // = 128 bits.

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Decrypt bytes previously encrypted with this class.
     *
     * @param dataToDecrypt    The data to decrypt
     * @param aesKey           The AES key to use for decryption
     * @return                 The decrypted bytes
     * @throws                 KeyCrypterException if bytes could not be decrypted
     */
    @Override
    public byte[] decrypt(EncryptedData dataToDecrypt, Key aesKey) throws KeyCrypterException {
        if(dataToDecrypt == null || aesKey == null) {
            throw new KeyCrypterException("Data and key to decrypt cannot be null");
        }

        try {
            ParametersWithIV keyWithIv = new ParametersWithIV(new KeyParameter(aesKey.getKeyBytes()), dataToDecrypt.getInitialisationVector());

            // Decrypt the message.
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance()));
            cipher.init(false, keyWithIv);

            byte[] cipherBytes = dataToDecrypt.getEncryptedBytes();
            byte[] decryptedBytes = new byte[cipher.getOutputSize(cipherBytes.length)];
            final int length1 = cipher.processBytes(cipherBytes, 0, cipherBytes.length, decryptedBytes, 0);
            final int length2 = cipher.doFinal(decryptedBytes, length1);

            byte[] decrypted = Arrays.copyOf(decryptedBytes, length1 + length2);
            Arrays.fill(decryptedBytes, (byte)0);
            return decrypted;
        } catch (InvalidCipherTextException e) {
            throw new KeyCrypterException.InvalidCipherText("Could not decrypt bytes", e);
        } catch (RuntimeException e) {
            throw new KeyCrypterException("Could not decrypt bytes", e);
        }
    }

    /**
     * Password based encryption using AES - CBC - PKCS7
     */
    @Override
    public EncryptedData encrypt(byte[] plainBytes, byte[] initializationVector, Key aesKey) throws KeyCrypterException {
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

            ParametersWithIV keyWithIv = new ParametersWithIV(new KeyParameter(aesKey.getKeyBytes()), iv);

            // Encrypt using AES.
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance()));
            cipher.init(true, keyWithIv);
            byte[] encryptedBytes = new byte[cipher.getOutputSize(plainBytes.length)];
            final int length1 = cipher.processBytes(plainBytes, 0, plainBytes.length, encryptedBytes, 0);
            final int length2 = cipher.doFinal(encryptedBytes, length1);

            return new EncryptedData(iv, Arrays.copyOf(encryptedBytes, length1 + length2), aesKey.getSalt(), aesKey.getDeriver(), getCrypterType());
        } catch (Exception e) {
            throw new KeyCrypterException("Could not encrypt bytes.", e);
        }
    }

    @Override
    public EncryptionType.Crypter getCrypterType() {
        return EncryptionType.Crypter.AES_CBC_PKCS7;
    }
}
