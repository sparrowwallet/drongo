package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.nio.ByteBuffer;

public class ChallengeResponseKeyDeriver implements AsymmetricKeyDeriver {
    private final AsymmetricKeyDeriver innerDeriver;
    private final ChallengeResponseProvider provider;

    public ChallengeResponseKeyDeriver(AsymmetricKeyDeriver innerDeriver, ChallengeResponseProvider provider) {
        this.innerDeriver = innerDeriver;
        this.provider = provider;
    }

    @Override
    public ECKey deriveECKey(CharSequence password) throws KeyCrypterException {
        ECKey innerKey = innerDeriver.deriveECKey(password);
        try {
            byte[] challenge = innerDeriver.getSalt();
            byte[] hmacResponse = provider.getResponse(challenge);

            byte[] innerKeyBytes = innerKey.getPrivKeyBytes();
            ByteBuffer buffer = ByteBuffer.allocate(innerKeyBytes.length + hmacResponse.length);
            buffer.put(innerKeyBytes);
            buffer.put(hmacResponse);

            byte[] combined = Sha256Hash.hash(buffer.array());
            return ECKey.fromPrivate(combined);
        } catch(ChallengeResponseException e) {
            throw new KeyCrypterException("Challenge-response failed: " + e.getMessage(), e);
        } finally {
            innerKey.clear();
        }
    }

    @Override
    public byte[] getSalt() {
        return innerDeriver.getSalt();
    }
}
