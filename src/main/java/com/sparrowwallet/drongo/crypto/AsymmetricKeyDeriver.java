package com.sparrowwallet.drongo.crypto;

public interface AsymmetricKeyDeriver {
    /**
     * Create a ECKey based on the provided password
     * @param password
     * @return ECKey The ECKey to use for encrypting and decrypting
     * @throws KeyCrypterException
     */
    ECKey deriveECKey(String password) throws KeyCrypterException;

    byte[] getSalt();
}
