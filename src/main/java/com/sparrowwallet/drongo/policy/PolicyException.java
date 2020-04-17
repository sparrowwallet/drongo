package com.sparrowwallet.drongo.policy;

public class PolicyException extends RuntimeException {
    public PolicyException() {
    }

    public PolicyException(String message) {
        super(message);
    }

    public PolicyException(String message, Throwable cause) {
        super(message, cause);
    }

    public PolicyException(Throwable cause) {
        super(cause);
    }

    public PolicyException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
