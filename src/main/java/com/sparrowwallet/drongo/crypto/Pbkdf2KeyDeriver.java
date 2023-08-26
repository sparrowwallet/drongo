package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.SecureString;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

public class Pbkdf2KeyDeriver implements KeyDeriver, AsymmetricKeyDeriver {
    public static final int DEFAULT_ITERATION_COUNT = 1024;
    public static final int DEFAULT_KEY_SIZE = 512;

    private final byte[] salt;
    private final int iterationCount;
    private final int keySize;

    public static final Pbkdf2KeyDeriver DEFAULT_INSTANCE = new Pbkdf2KeyDeriver();

    public Pbkdf2KeyDeriver() {
        this.salt = new byte[0];
        this.iterationCount = DEFAULT_ITERATION_COUNT;
        this.keySize = DEFAULT_KEY_SIZE;
    }

    public Pbkdf2KeyDeriver(byte[] salt) {
        this.salt = salt;
        this.iterationCount = DEFAULT_ITERATION_COUNT;
        this.keySize = DEFAULT_KEY_SIZE;
    }

    public Pbkdf2KeyDeriver(byte[] salt, int iterationCount) {
        this.salt = salt;
        this.iterationCount = iterationCount;
        this.keySize = DEFAULT_KEY_SIZE;
    }

    public Pbkdf2KeyDeriver(byte[] salt, int iterationCount, int keySize) {
        this.salt = salt;
        this.iterationCount = iterationCount;
        this.keySize = keySize;
    }

    @Override
    public byte[] getSalt() {
        return salt;
    }

    @Override
    public Key deriveKey(CharSequence password) throws KeyCrypterException {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
        gen.init(SecureString.toBytesUTF8(password), salt, iterationCount);
        byte[] keyBytes = ((KeyParameter)gen.generateDerivedParameters(keySize)).getKey();
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
