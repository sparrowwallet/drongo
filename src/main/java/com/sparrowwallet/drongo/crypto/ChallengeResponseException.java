package com.sparrowwallet.drongo.crypto;

public class ChallengeResponseException extends Exception {
    public ChallengeResponseException(String message) {
        super(message);
    }

    public ChallengeResponseException(String message, Throwable cause) {
        super(message, cause);
    }
}
