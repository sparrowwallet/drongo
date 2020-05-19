package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.SecureString;

import java.util.Objects;

public class EncryptionType {
    public enum Deriver {
        NONE() {
            public KeyDeriver getKeyDeriver() {
                return new KeyDeriver() {
                    @Override
                    public Key deriveKey(CharSequence password) throws KeyCrypterException {
                        return new Key(SecureString.toBytesUTF8(password), null, NONE);
                    }

                    @Override
                    public Deriver getDeriverType() {
                        return NONE;
                    }
                };
            }
        },
        DOUBLE_SHA256() {
            public KeyDeriver getKeyDeriver() {
                return new DoubleSha256KeyDeriver();
            }
        },
        PBKDF2() {
            public KeyDeriver getKeyDeriver() {
                return new Pbkdf2KeyDeriver();
            }

            @Override
            public KeyDeriver getKeyDeriver(byte[] salt) {
                return new Pbkdf2KeyDeriver(salt);
            }
        },
        SCRYPT() {
            public KeyDeriver getKeyDeriver() {
                return new ScryptKeyDeriver();
            }

            @Override
            public KeyDeriver getKeyDeriver(byte[] salt) {
                return new ScryptKeyDeriver(salt);
            }
        },
        ARGON2() {
            public KeyDeriver getKeyDeriver() {
                return new Argon2KeyDeriver();
            }

            public KeyDeriver getKeyDeriver(byte[] salt) {
                return new Argon2KeyDeriver(salt);
            }
        };

        public abstract KeyDeriver getKeyDeriver();

        public KeyDeriver getKeyDeriver(byte[] salt) {
            return getKeyDeriver();
        }
    }

    public enum Crypter {
        NONE() {
            @Override
            public KeyCrypter getKeyCrypter() {
                return new KeyCrypter() {
                    @Override
                    public byte[] decrypt(EncryptedData encryptedBytesToDecode, Key key) throws KeyCrypterException {
                        return encryptedBytesToDecode.getEncryptedBytes();
                    }

                    @Override
                    public EncryptedData encrypt(byte[] plainBytes, byte[] initializationVector, Key key) throws KeyCrypterException {
                        return new EncryptedData(plainBytes, initializationVector, key.getSalt(), key.getDeriver(), NONE);
                    }

                    @Override
                    public Crypter getCrypterType() {
                        return NONE;
                    }
                };
            }
        },
        AES_CBC_PKCS7() {
            @Override
            public KeyCrypter getKeyCrypter() {
                return new AESKeyCrypter();
            }
        };

        public abstract KeyCrypter getKeyCrypter();
    }

    private final Deriver deriver;
    private final Crypter crypter;

    public EncryptionType(Deriver deriver, Crypter crypter) {
        this.deriver = deriver;
        this.crypter = crypter;
    }

    public Deriver getDeriver() {
        return deriver;
    }

    public Crypter getCrypter() {
        return crypter;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptionType that = (EncryptionType) o;
        return deriver == that.deriver &&
                crypter == that.crypter;
    }

    @Override
    public int hashCode() {
        return Objects.hash(deriver, crypter);
    }

    @Override
    public String toString() {
        return "EncryptionType[" +
                "deriver=" + deriver +
                ", crypter=" + crypter +
                ']';
    }
}
