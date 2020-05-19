package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.SecureString;
import com.sparrowwallet.drongo.protocol.Sha256Hash;

public class DoubleSha256KeyDeriver implements KeyDeriver {

    @Override
    public Key deriveKey(CharSequence password) throws KeyCrypterException {
        byte[] passwordBytes = SecureString.toBytesUTF8(password);
        byte[] sha256 = Sha256Hash.hash(passwordBytes);
        byte[] doubleSha256 = Sha256Hash.hash(sha256);
        return new Key(doubleSha256, null, getDeriverType());
    }

    @Override
    public EncryptionType.Deriver getDeriverType() {
        return EncryptionType.Deriver.DOUBLE_SHA256;
    }
}
