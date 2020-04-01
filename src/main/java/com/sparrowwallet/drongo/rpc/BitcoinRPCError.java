package com.sparrowwallet.drongo.rpc;

import java.util.Map;

public class BitcoinRPCError {
    private int code;
    private String message;

    @SuppressWarnings({ "rawtypes" })
    public BitcoinRPCError(Map errorMap) {
        Number n = (Number) errorMap.get("code");
        this.code    = n != null ? n.intValue() : 0;
        this.message = (String) errorMap.get("message");
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
