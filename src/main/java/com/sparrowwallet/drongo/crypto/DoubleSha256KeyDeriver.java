package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.nio.charset.StandardCharsets;

public class DoubleSha256KeyDeriver implements KeyDeriver {

    @Override
    public Key deriveKey(String password) throws KeyCrypterException {
        byte[] sha256 = Sha256Hash.hash(password.getBytes(StandardCharsets.UTF_8));
        byte[] doubleSha256 = Sha256Hash.hash(sha256);
        return new Key(doubleSha256, null, getDeriverType());
    }

    @Override
    public EncryptionType.Deriver getDeriverType() {
        return EncryptionType.Deriver.DOUBLE_SHA256;
    }
}
