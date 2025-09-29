package com.sparrowwallet.drongo.silentpayments;

public class InvalidSilentPaymentException extends Exception {
    public InvalidSilentPaymentException(String message) {
        super(message);
    }

    public InvalidSilentPaymentException(String message, Throwable cause) {
        super(message, cause);
    }
}
