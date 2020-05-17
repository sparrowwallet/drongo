package com.sparrowwallet.drongo.crypto;

public interface KeyCrypter {
    /**
     * Decrypt the provided encrypted bytes, converting them into unencrypted bytes.
     *
     * @throws KeyCrypterException if decryption was unsuccessful.
     */
    byte[] decrypt(EncryptedData encryptedBytesToDecode, Key key) throws KeyCrypterException;

    /**
     * Encrypt the supplied bytes, converting them into ciphertext.
     *
     * @return EncryptedData An EncryptedData object containing the encrypted bytes and an initialisation vector and key salt.
     * @throws KeyCrypterException if encryption was unsuccessful
     */
    EncryptedData encrypt(byte[] plainBytes, byte[] initializationVector, Key key) throws KeyCrypterException;

    EncryptionType.Crypter getCrypterType();
}
