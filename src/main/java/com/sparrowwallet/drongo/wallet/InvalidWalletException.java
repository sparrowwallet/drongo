package com.sparrowwallet.drongo.wallet;

public class InvalidWalletException extends Exception {
    public InvalidWalletException() {
        super();
    }

    public InvalidWalletException(String msg) {
        super(msg);
    }

    public InvalidWalletException(String msg, Throwable throwable) {
        super(msg, throwable);
    }
}
