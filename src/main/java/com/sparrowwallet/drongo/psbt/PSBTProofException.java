package com.sparrowwallet.drongo.psbt;

public class PSBTProofException extends PSBTParseException {
    public PSBTProofException() {
        super();
    }

    public PSBTProofException(String message) {
        super(message);
    }

    public PSBTProofException(Throwable cause) {
        super(cause);
    }

    public PSBTProofException(String message, Throwable cause) {
        super(message, cause);
    }
}
