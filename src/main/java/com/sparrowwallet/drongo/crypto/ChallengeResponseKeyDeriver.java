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
        byte[] innerKeyBytes = null;
        byte[] hmacResponse = null;
        byte[] bufferArray = null;
        byte[] combined = null;
        try {
            byte[] challenge = innerDeriver.getSalt();
            hmacResponse = provider.getResponse(challenge);
            innerKeyBytes = innerKey.getPrivKeyBytes();

            ByteBuffer buffer = ByteBuffer.allocate(innerKeyBytes.length + hmacResponse.length);
            buffer.put(innerKeyBytes);
            buffer.put(hmacResponse);
            bufferArray = buffer.array();

            combined = Sha256Hash.hash(bufferArray);
            return ECKey.fromPrivate(combined);
        } catch(ChallengeResponseException e) {
            throw new KeyCrypterException(e.getMessage(), e);
        } finally {
            if(innerKeyBytes != null) Arrays.fill(innerKeyBytes, (byte) 0);
            if(hmacResponse != null) Arrays.fill(hmacResponse, (byte) 0);
            if(bufferArray != null) Arrays.fill(bufferArray, (byte) 0);
            if(combined != null) Arrays.fill(combined, (byte) 0);
            innerKey.clear();
        }
    }

    @Override
    public byte[] getSalt() {
        return innerDeriver.getSalt();
    }
}
