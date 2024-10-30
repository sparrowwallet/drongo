package com.sparrowwallet.drongo.crypto;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class Secp256r1Key {
    private static final X9ECParameters CURVE_PARAMS = ECNamedCurveTable.getByName("P-256");

    public static final ECDomainParameters CURVE;

    private final ECPoint point;

    static {
        CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
    }

    public Secp256r1Key(byte[] publicKeyBytes) {
        this.point = CURVE.getCurve().decodePoint(publicKeyBytes);
    }

    public boolean verify(byte[] challenge, byte[] challengeSignature) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, new ECPublicKeyParameters(point, CURVE));

        int halfLength = challengeSignature.length / 2;
        byte[] r = new byte[halfLength];
        byte[] s = new byte[halfLength];
        System.arraycopy(challengeSignature, 0, r, 0, halfLength);
        System.arraycopy(challengeSignature, halfLength, s, 0, halfLength);

        return signer.verifySignature(challenge, new BigInteger(1, r), new BigInteger(1, s));
    }
}
