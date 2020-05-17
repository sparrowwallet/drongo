package com.sparrowwallet.drongo.crypto;

/**
 * Provides a uniform way to access something that can be optionally encrypted with a
 * {@link KeyCrypter}, yielding an {@link EncryptedData}, and
 * which can have a creation time associated with it.
 */
public interface EncryptableItem {
    /** Returns whether the item is encrypted or not. If it is, then {@link #getSecretBytes()} will return null. */
    boolean isEncrypted();

    /** Returns the raw bytes of the item, if not encrypted, or null if encrypted or the secret is missing. */
    byte[] getSecretBytes();

    /** Returns the initialization vector and encrypted secret bytes, or null if not encrypted. */
    EncryptedData getEncryptedData();

    /** Returns an object containing enums describing which algorithms are used to derive the key and encrypt the data. */
    EncryptionType getEncryptionType();

    /** Returns the time in seconds since the UNIX epoch at which this encryptable item was first created/derived. */
    long getCreationTimeSeconds();
}
