package com.sparrowwallet.drongo.bip47;

public class InvalidPaymentCodeException extends Exception {
    public InvalidPaymentCodeException() {
        super();
    }

    public InvalidPaymentCodeException(String msg) {
        super(msg);
    }

    public InvalidPaymentCodeException(Throwable cause) {
        super(cause);
    }

    public InvalidPaymentCodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
