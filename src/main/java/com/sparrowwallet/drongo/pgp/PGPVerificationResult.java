package com.sparrowwallet.drongo.pgp;

import java.util.Date;

public record PGPVerificationResult(long keyId, String userId, Date signatureTimestamp, boolean expired, boolean userProvidedKey) { }
