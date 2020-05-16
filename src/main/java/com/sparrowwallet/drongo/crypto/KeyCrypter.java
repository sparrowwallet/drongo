package com.sparrowwallet.drongo.crypto;

/**
 * <p>A KeyCrypter can be used to encrypt and decrypt a message. The sequence of events to encrypt and then decrypt
 * a message are as follows:</p>
 *
 * <p>(1) Ask the user for a password. deriveKey() is then called to create an Key. This contains the AES
 * key that will be used for encryption.</p>
 * <p>(2) Encrypt the message using encrypt(), providing the message bytes and the Key from (1). This returns
 * an EncryptedData which contains the encryptedPrivateKey bytes and an initialisation vector.</p>
 * <p>(3) To decrypt an EncryptedData, repeat step (1) to get a Key, then call decrypt().</p>
 *
 * <p>There can be different algorithms used for encryption/ decryption so the getUnderstoodEncryptionType is used
 * to determine whether any given KeyCrypter can understand the type of encrypted data you have.</p>
 */
public interface KeyCrypter {

    /**
     * Return the EncryptionType enum value which denotes the type of encryption/ decryption that this KeyCrypter
     * can understand.
     */
    EncryptionType getUnderstoodEncryptionType();

    /**
     * Create a Key (which typically contains an AES key)
     * @param password
     * @return Key The Key which typically contains the AES key to use for encrypting and decrypting
     * @throws KeyCrypterException
     */
    Key deriveKey(CharSequence password) throws KeyCrypterException;

    /**
     * Decrypt the provided encrypted bytes, converting them into unencrypted bytes.
     *
     * @throws KeyCrypterException if decryption was unsuccessful.
     */
    byte[] decrypt(EncryptedData encryptedBytesToDecode, Key key) throws KeyCrypterException;

    /**
     * Encrypt the supplied bytes, converting them into ciphertext.
     *
     * @return encryptedPrivateKey An encryptedPrivateKey containing the encrypted bytes and an initialisation vector.
     * @throws KeyCrypterException if encryption was unsuccessful
     */
    EncryptedData encrypt(byte[] plainBytes, byte[] initializationVector, Key key) throws KeyCrypterException;
}
