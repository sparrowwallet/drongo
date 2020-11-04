package com.sparrowwallet.drongo.wallet;

public class InvalidKeystoreException extends Exception {
    public InvalidKeystoreException() {
        super();
    }

    public InvalidKeystoreException(String msg) {
        super(msg);
    }

    public InvalidKeystoreException(String msg, Throwable throwable) {
        super(msg, throwable);
    }
}
