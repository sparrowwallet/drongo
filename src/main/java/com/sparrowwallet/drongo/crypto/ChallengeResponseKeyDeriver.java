package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.nio.ByteBuffer;
import java.util.Arrays;

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
            try {
                ByteBuffer buffer = ByteBuffer.allocate(innerKeyBytes.length + hmacResponse.length);
                buffer.put(innerKeyBytes);
                buffer.put(hmacResponse);

                byte[] combined = Sha256Hash.hash(buffer.array());
                try {
                    return ECKey.fromPrivate(combined);
                } finally {
                    Arrays.fill(buffer.array(), (byte) 0);
                    Arrays.fill(combined, (byte) 0);
                }
            } finally {
                Arrays.fill(innerKeyBytes, (byte) 0);
                Arrays.fill(hmacResponse, (byte) 0);
            }
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
