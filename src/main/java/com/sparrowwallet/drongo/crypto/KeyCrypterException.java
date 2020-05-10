package com.sparrowwallet.drongo.crypto;

/**
 * <p>Exception to provide the following:</p>
 * <ul>
 * <li>Provision of encryption / decryption exception</li>
 * </ul>
 * <p>This base exception acts as a general failure mode not attributable to a specific cause (other than
 * that reported in the exception message). Since this is in English, it may not be worth reporting directly
 * to the user other than as part of a "general failure to parse" response.</p>
 */
public class KeyCrypterException extends RuntimeException {
    public KeyCrypterException(String s) {
        super(s);
    }

    public KeyCrypterException(String s, Throwable throwable) {
        super(s, throwable);
    }

    /**
     * This exception is thrown when a private key or seed is decrypted, it doesn't match its public key any
     * more. This likely means the wrong decryption key has been used.
     */
    public static class PublicPrivateMismatch extends KeyCrypterException {
        public PublicPrivateMismatch(String message) {
            super(message);
        }

        public PublicPrivateMismatch(String message, Throwable throwable) {
            super(message, throwable);
        }
    }

    /**
     * This exception is thrown when a private key or seed is decrypted, the decrypted message is damaged
     * (e.g. the padding is damaged). This likely means the wrong decryption key has been used.
     */
    public static class InvalidCipherText extends KeyCrypterException {
        public InvalidCipherText(String message) {
            super(message);
        }

        public InvalidCipherText(String message, Throwable throwable) {
            super(message, throwable);
        }
    }
}
