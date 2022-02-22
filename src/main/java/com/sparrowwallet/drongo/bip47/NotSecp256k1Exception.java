package com.sparrowwallet.drongo.bip47;

public class NotSecp256k1Exception extends Exception {
    public NotSecp256k1Exception() {
        super();
    }

    public NotSecp256k1Exception(String msg) {
        super(msg);
    }

    public NotSecp256k1Exception(Throwable cause) {
        super(cause);
    }

    public NotSecp256k1Exception(String message, Throwable cause) {
        super(message, cause);
    }
}
