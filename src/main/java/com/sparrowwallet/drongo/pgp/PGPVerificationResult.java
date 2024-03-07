package com.sparrowwallet.drongo.pgp;

import java.util.Date;

public record PGPVerificationResult(long keyId, String userId, String fingerprint, Date signatureTimestamp, boolean expired, PGPKeySource keySource) { }
