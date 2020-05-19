package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

public class Pbkdf2KeyDeriver implements KeyDeriver, AsymmetricKeyDeriver {
    public static final int DEFAULT_ITERATION_COUNT = 1024;

    private final byte[] salt;
    private final int iterationCount;

    public static final Pbkdf2KeyDeriver DEFAULT_INSTANCE = new Pbkdf2KeyDeriver();

    public Pbkdf2KeyDeriver() {
        this.salt = new byte[0];
        this.iterationCount = DEFAULT_ITERATION_COUNT;
    }

    public Pbkdf2KeyDeriver(byte[] salt) {
        this.salt = salt;
        this.iterationCount = DEFAULT_ITERATION_COUNT;
    }

    public Pbkdf2KeyDeriver(byte[] salt, int iterationCount) {
        this.salt = salt;
        this.iterationCount = iterationCount;
    }

    @Override
    public byte[] getSalt() {
        return salt;
    }

    @Override
    public Key deriveKey(CharSequence password) throws KeyCrypterException {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
        gen.init(Utils.toBytesUTF8(password), salt, iterationCount);
        byte[] keyBytes = ((KeyParameter)gen.generateDerivedParameters(512)).getKey();
        return new Key(keyBytes, salt, getDeriverType());
    }

    @Override
    public ECKey deriveECKey(CharSequence password) throws KeyCrypterException {
        Key key = deriveKey(password);
        return ECKey.fromPrivate(key.getKeyBytes());
    }

    @Override
    public EncryptionType.Deriver getDeriverType() {
        return EncryptionType.Deriver.PBKDF2;
    }
}
