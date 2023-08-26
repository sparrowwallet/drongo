package com.sparrowwallet.drongo.wallet;

public class InsufficientFundsException extends Exception {
    private Long targetValue;

    public InsufficientFundsException() {
        super();
    }

    public InsufficientFundsException(String msg) {
        super(msg);
    }

    public InsufficientFundsException(String message, Long targetValue) {
        super(message);
        this.targetValue = targetValue;
    }

    public Long getTargetValue() {
        return targetValue;
    }
}
