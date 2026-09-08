package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class ChallengeResponseKeyDeriverTest {
    private static final byte[] SALT = Utils.hexToBytes("000102030405060708090a0b0c0d0e0f");

    private static ChallengeResponseProvider fixedResponse(byte[] response) {
        return challenge -> Arrays.copyOf(response, response.length);
    }

    private static byte[] hmacOfLength(int length, byte fill) {
        byte[] response = new byte[length];
        Arrays.fill(response, fill);
        return response;
    }

    @Test
    public void derivesCombinedKey() {
        Argon2KeyDeriver inner = new Argon2KeyDeriver(SALT);
        byte[] response = hmacOfLength(20, (byte)0x5a);
        ChallengeResponseKeyDeriver deriver = new ChallengeResponseKeyDeriver(inner, fixedResponse(response));

        ECKey derived = deriver.deriveECKey("password");

        byte[] innerKeyBytes = inner.deriveECKey("password").getPrivKeyBytes();
        ByteBuffer buffer = ByteBuffer.allocate(innerKeyBytes.length + response.length);
        buffer.put(innerKeyBytes);
        buffer.put(response);
        ECKey expected = ECKey.fromPrivate(Sha256Hash.hash(buffer.array()));

        Assertions.assertEquals(expected, derived);
    }

    @Test
    public void isDeterministic() {
        Argon2KeyDeriver inner = new Argon2KeyDeriver(SALT);
        ChallengeResponseKeyDeriver deriver = new ChallengeResponseKeyDeriver(inner, fixedResponse(hmacOfLength(20, (byte)0x11)));

        Assertions.assertEquals(deriver.deriveECKey("password"), deriver.deriveECKey("password"));
    }

    @Test
    public void differentResponseGivesDifferentKey() {
        Argon2KeyDeriver inner = new Argon2KeyDeriver(SALT);
        ECKey first = new ChallengeResponseKeyDeriver(inner, fixedResponse(hmacOfLength(20, (byte)0x01))).deriveECKey("password");
        ECKey second = new ChallengeResponseKeyDeriver(inner, fixedResponse(hmacOfLength(20, (byte)0x02))).deriveECKey("password");

        Assertions.assertNotEquals(first, second);
    }

    @Test
    public void differentPasswordGivesDifferentKey() {
        Argon2KeyDeriver inner = new Argon2KeyDeriver(SALT);
        ChallengeResponseKeyDeriver deriver = new ChallengeResponseKeyDeriver(inner, fixedResponse(hmacOfLength(20, (byte)0x33)));

        Assertions.assertNotEquals(deriver.deriveECKey("password"), deriver.deriveECKey("other"));
    }

    @Test
    public void differsFromInnerDeriverAlone() {
        Argon2KeyDeriver inner = new Argon2KeyDeriver(SALT);
        ChallengeResponseKeyDeriver deriver = new ChallengeResponseKeyDeriver(inner, fixedResponse(hmacOfLength(20, (byte)0x44)));

        Assertions.assertNotEquals(inner.deriveECKey("password"), deriver.deriveECKey("password"));
    }

    @Test
    public void challengeIsTheInnerSalt() {
        Argon2KeyDeriver inner = new Argon2KeyDeriver(SALT);
        byte[][] seen = new byte[1][];
        ChallengeResponseKeyDeriver deriver = new ChallengeResponseKeyDeriver(inner, challenge -> {
            seen[0] = challenge;
            return hmacOfLength(20, (byte)0x55);
        });

        deriver.deriveECKey("password");

        Assertions.assertArrayEquals(SALT, seen[0]);
        Assertions.assertArrayEquals(SALT, deriver.getSalt());
    }

    @Test
    public void deviceFailureBecomesKeyCrypterExceptionPreservingMessage() {
        Argon2KeyDeriver inner = new Argon2KeyDeriver(SALT);
        ChallengeResponseKeyDeriver deriver = new ChallengeResponseKeyDeriver(inner, challenge -> {
            throw new ChallengeResponseException("Security key timed out waiting for touch");
        });

        KeyCrypterException e = Assertions.assertThrows(KeyCrypterException.class, () -> deriver.deriveECKey("password"));
        Assertions.assertEquals("Security key timed out waiting for touch", e.getMessage());
        Assertions.assertInstanceOf(ChallengeResponseException.class, e.getCause());
    }

    @Test
    public void acceptsResponseLengthsOtherThanTwenty() {
        Argon2KeyDeriver inner = new Argon2KeyDeriver(SALT);
        ECKey key = new ChallengeResponseKeyDeriver(inner, fixedResponse(hmacOfLength(32, (byte)0x66))).deriveECKey("password");

        Assertions.assertNotNull(key);
    }

    @Test
    public void emptyPasswordStillMixesTheResponse() {
        Argon2KeyDeriver inner = new Argon2KeyDeriver(SALT);
        ChallengeResponseKeyDeriver deriver = new ChallengeResponseKeyDeriver(inner, fixedResponse(hmacOfLength(20, (byte)0x77)));

        Assertions.assertNotEquals(inner.deriveECKey(""), deriver.deriveECKey(""));
    }
}
