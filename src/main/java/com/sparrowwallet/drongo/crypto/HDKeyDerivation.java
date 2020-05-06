package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class HDKeyDerivation {
    public static final String BITCOIN_SEED_KEY = "Bitcoin seed";

    public static DeterministicKey createMasterPrivateKey(byte[] seed) throws HDDerivationException {
        byte[] hmacSha512 = Utils.getHmacSha512Hash(BITCOIN_SEED_KEY.getBytes(StandardCharsets.UTF_8), seed);
        byte[] privKeyBytes = Arrays.copyOfRange(hmacSha512, 0, 32);
        byte[] chainCode = Arrays.copyOfRange(hmacSha512, 32, 64);
        Arrays.fill(hmacSha512, (byte)0);
        DeterministicKey masterPrivKey = createMasterPrivKeyFromBytes(privKeyBytes, chainCode);
        Arrays.fill(privKeyBytes, (byte)0);
        Arrays.fill(chainCode, (byte)0);
        return masterPrivKey;
    }

    public static DeterministicKey createMasterPrivKeyFromBytes(byte[] privKeyBytes, byte[] chainCode) throws HDDerivationException {
        // childNumberPath is an empty list because we are creating the root key.
        return createMasterPrivKeyFromBytes(privKeyBytes, chainCode, Collections.emptyList());
    }

    public static DeterministicKey createMasterPrivKeyFromBytes(byte[] privKeyBytes, byte[] chainCode, List<ChildNumber> childNumberPath) throws HDDerivationException {
        BigInteger priv = new BigInteger(1, privKeyBytes);
        if(priv.equals(BigInteger.ZERO) || priv.compareTo(ECKey.CURVE.getN()) > 0) {
            throw new HDDerivationException("Private key bytes are not valid");
        }

        return new DeterministicKey(childNumberPath, chainCode, priv, null);
    }

    public static DeterministicKey deriveChildKey(DeterministicKey parent, ChildNumber childNumber) throws HDDerivationException {
        RawKeyBytes rawKey = deriveChildKeyBytesFromPublic(parent, childNumber);
        return new DeterministicKey(Utils.appendChild(parent.getPath(), childNumber), rawKey.chainCode, new LazyECPoint(ECKey.CURVE.getCurve(), rawKey.keyBytes), parent);
    }

    public static RawKeyBytes deriveChildKeyBytesFromPublic(DeterministicKey parent, ChildNumber childNumber) throws HDDerivationException {
        if(childNumber.isHardened()) {
            throw new HDDerivationException("Can't use private derivation with public keys only.");
        }

        byte[] parentPublicKey = parent.getPubKeyPoint().getEncoded(true);
        if(parentPublicKey.length != 33) {
            throw new HDDerivationException("Parent pubkey must be 33 bytes, but is " + parentPublicKey.length);
        }

        ByteBuffer data = ByteBuffer.allocate(37);
        data.put(parentPublicKey);
        data.putInt(childNumber.i());
        byte[] i = Utils.getHmacSha512Hash(parent.getChainCode(), data.array());
        if(i.length != 64) {
            throw new HDDerivationException("HmacSHA512 output must be 64 bytes, is" + i.length);
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
