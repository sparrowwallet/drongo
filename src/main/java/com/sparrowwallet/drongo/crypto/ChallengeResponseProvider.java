package com.sparrowwallet.drongo.crypto;

public interface ChallengeResponseProvider {
    byte[] getResponse(byte[] challenge) throws ChallengeResponseException;

    String getName();
}
