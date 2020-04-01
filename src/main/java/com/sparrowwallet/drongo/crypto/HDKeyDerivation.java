package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class HDKeyDerivation {
    public static DeterministicKey deriveChildKey(DeterministicKey parent, ChildNumber childNumber) {
        RawKeyBytes rawKey = deriveChildKeyBytesFromPublic(parent, childNumber);
        return new DeterministicKey(Utils.appendChild(parent.getPath(), childNumber), rawKey.chainCode, new LazyECPoint(ECKey.CURVE.getCurve(), rawKey.keyBytes), parent);
    }

    public static RawKeyBytes deriveChildKeyBytesFromPublic(DeterministicKey parent, ChildNumber childNumber) {
        if(childNumber.isHardened()) {
            throw new IllegalArgumentException("Can't use private derivation with public keys only.");
        }

        byte[] parentPublicKey = parent.getPubKeyPoint().getEncoded(true);
        if(parentPublicKey.length != 33) {
            throw new IllegalArgumentException("Parent pubkey must be 33 bytes, but is " + parentPublicKey.length);
        }

        ByteBuffer data = ByteBuffer.allocate(37);
        data.put(parentPublicKey);
        data.putInt(childNumber.i());
        byte[] i = Utils.hmacSha512(parent.getChainCode(), data.array());
        if(i.length != 64) {
            throw new IllegalStateException("HmacSHA512 output must be 64 bytes, is" + i.length);
        }

        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] chainCode = Arrays.copyOfRange(i, 32, 64);
        BigInteger ilInt = new BigInteger(1, il);

        final BigInteger N = ECKey.CURVE.getN();
        ECPoint Ki = ECKey.publicPointFromPrivate(ilInt).add(parent.getPubKeyPoint());

        return new RawKeyBytes(Ki.getEncoded(true), chainCode);
    }

    public static class RawKeyBytes {
        public final byte[] keyBytes, chainCode;

        public RawKeyBytes(byte[] keyBytes, byte[] chainCode) {
            this.keyBytes = keyBytes;
            this.chainCode = chainCode;
        }
    }
}
