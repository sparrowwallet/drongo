package com.sparrowwallet.drongo.crypto;

public interface KeyDeriver {
    /**
     * Create a Key (which typically contains an AES key)
     * @param password
     * @return Key The Key which typically contains the AES key to use for encrypting and decrypting
     * @throws KeyCrypterException
     */
    Key deriveKey(CharSequence password) throws KeyCrypterException;

    EncryptionType.Deriver getDeriverType();
}
