package com.sparrowwallet.drongo.crypto;

public class Argon2KeyDeriver implements KeyDeriver {
    @Override
    public Key deriveKey(String password) throws KeyCrypterException {
        return null;
    }

    @Override
    public EncryptionType.Deriver getDeriverType() {
        return EncryptionType.Deriver.ARGON2;
    }
}
