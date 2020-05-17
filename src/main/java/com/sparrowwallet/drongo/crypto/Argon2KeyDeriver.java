package com.sparrowwallet.drongo.crypto;

import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Argon2KeyDeriver implements KeyDeriver {
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;
    private static final int ITERATIONS = 10;
    private static final int MEMORY = 256 * 1024;
    private static final int PARALLELISM = 4;

    private final byte[] salt;

    public Argon2KeyDeriver() {
        SecureRandom secureRandom = new SecureRandom();
        salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
    }

    public Argon2KeyDeriver(byte[] salt) {
        this.salt = salt;
    }

    @Override
    public Key deriveKey(String password) throws KeyCrypterException {
        Argon2Advanced argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id, SALT_LENGTH, HASH_LENGTH);
        byte[] hash = argon2.rawHash(ITERATIONS, MEMORY, PARALLELISM, password.getBytes(StandardCharsets.UTF_8), salt);
        return new Key(hash, salt, getDeriverType());
    }

    @Override
    public EncryptionType.Deriver getDeriverType() {
        return EncryptionType.Deriver.ARGON2;
    }
}
