package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.SecureString;
import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;

import java.security.SecureRandom;

public class Argon2KeyDeriver implements KeyDeriver, AsymmetricKeyDeriver {
    public static final Argon2Parameters TEST_PARAMETERS = new Argon2Parameters(16, 32, 1, 1024, 1);
    public static final Argon2Parameters SPRW1_PARAMETERS = new Argon2Parameters(16, 32, 10, 256 * 1024, 4);

    private final Argon2Parameters argon2Parameters;
    private final byte[] salt;

    public Argon2KeyDeriver() {
        this(isTest() ? TEST_PARAMETERS : SPRW1_PARAMETERS);
    }

    public Argon2KeyDeriver(Argon2Parameters argon2Parameters) {
        this.argon2Parameters = argon2Parameters;

        SecureRandom secureRandom = new SecureRandom();
        salt = new byte[argon2Parameters.saltLength];
        secureRandom.nextBytes(salt);
    }

    public Argon2KeyDeriver(byte[] salt) {
        this(isTest() ? TEST_PARAMETERS : SPRW1_PARAMETERS, salt);
    }

    public Argon2KeyDeriver(Argon2Parameters argon2Parameters, byte[] salt) {
        this.argon2Parameters = argon2Parameters;
        this.salt = salt;
    }

    @Override
    public byte[] getSalt() {
        return salt;
    }

    @Override
    public Key deriveKey(CharSequence password) throws KeyCrypterException {
        Argon2Advanced argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id, argon2Parameters.saltLength, argon2Parameters.hashLength);
        byte[] hash = argon2.rawHash(argon2Parameters.iterations, argon2Parameters.memory, argon2Parameters.parallelism, SecureString.toBytesUTF8(password), salt);
        return new Key(hash, salt, getDeriverType());
    }

    @Override
    public ECKey deriveECKey(CharSequence password) throws KeyCrypterException {
        Key key = deriveKey(password);
        return ECKey.fromPrivate(key.getKeyBytes());
    }

    @Override
    public EncryptionType.Deriver getDeriverType() {
        return EncryptionType.Deriver.ARGON2;
    }

    private static boolean isTest() {
        return System.getProperty("org.gradle.test.worker") != null;
    }

    public static class Argon2Parameters {
        public final int saltLength;
        public final int hashLength;
        public final int iterations;
        public final int memory;
        public final int parallelism;

        public Argon2Parameters(int saltLength, int hashLength, int iterations, int memory, int parallelism) {
            this.saltLength = saltLength;
            this.hashLength = hashLength;
            this.iterations = iterations;
            this.memory = memory;
            this.parallelism = parallelism;
        }
    }
}
