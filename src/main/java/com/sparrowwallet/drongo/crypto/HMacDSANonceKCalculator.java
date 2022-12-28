package com.sparrowwallet.drongo.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.sparrowwallet.drongo.Utils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * A deterministic K calculator based on the algorithm in section 3.2 of RFC 6979.
 * This is a copy of org.bouncycastle.crypto.signers.HMacDSAKCalculator, with support for section 3.6 of RFC 6979 (additional data)
 */
public class HMacDSANonceKCalculator implements DSAKCalculator {
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    private final HMac hMac;
    private final byte[] K;
    private final byte[] V;
    private final Long counter;

    private BigInteger n;

    /**
     * Base constructor.
     *
     * @param digest digest to build the HMAC on.
     * @param counter additional data as per RFC 6979 3.6
     */
    public HMacDSANonceKCalculator(Digest digest, Integer counter) {
        this.hMac = new HMac(digest);
        this.V = new byte[hMac.getMacSize()];
        this.K = new byte[hMac.getMacSize()];
        this.counter = (counter == null ? null : Integer.toUnsignedLong(counter));
    }

    public boolean isDeterministic()
    {
        return true;
    }

    public void init(BigInteger n, SecureRandom random)
    {
        throw new IllegalStateException("Operation not supported");
    }

    public void init(BigInteger n, BigInteger d, byte[] message)
    {
        this.n = n;

        Arrays.fill(V, (byte)0x01);
        Arrays.fill(K, (byte)0);

        int size = BigIntegers.getUnsignedByteLength(n);
        byte[] x = new byte[size];
        byte[] dVal = BigIntegers.asUnsignedByteArray(d);

        System.arraycopy(dVal, 0, x, x.length - dVal.length, dVal.length);

        byte[] m = new byte[size];

        BigInteger mInt = bitsToInt(message);

        if (mInt.compareTo(n) >= 0)
        {
            mInt = mInt.subtract(n);
        }

        byte[] mVal = BigIntegers.asUnsignedByteArray(mInt);

        System.arraycopy(mVal, 0, m, m.length - mVal.length, mVal.length);

        byte[] c = null;
        if(counter != null) {
            BigInteger additional = BigInteger.valueOf(counter);
            c = Utils.bigIntegerToBytes(additional, size);
            Utils.reverse(c);
        }

        hMac.init(new KeyParameter(K));

        hMac.update(V, 0, V.length);
        hMac.update((byte)0x00);
        hMac.update(x, 0, x.length);
        hMac.update(m, 0, m.length);
        if(c != null) {
            hMac.update(c, 0, c.length);
        }

        hMac.doFinal(K, 0);

        hMac.init(new KeyParameter(K));

        hMac.update(V, 0, V.length);

        hMac.doFinal(V, 0);

        hMac.update(V, 0, V.length);
        hMac.update((byte)0x01);
        hMac.update(x, 0, x.length);
        hMac.update(m, 0, m.length);
        if(counter != null) {
            hMac.update(c, 0, c.length);
        }

        hMac.doFinal(K, 0);

        hMac.init(new KeyParameter(K));

        hMac.update(V, 0, V.length);

        hMac.doFinal(V, 0);
    }

    public BigInteger nextK()
    {
        byte[] t = new byte[BigIntegers.getUnsignedByteLength(n)];

        for (;;)
        {
            int tOff = 0;

            while (tOff < t.length)
            {
                hMac.update(V, 0, V.length);

                hMac.doFinal(V, 0);

                int len = Math.min(t.length - tOff, V.length);
                System.arraycopy(V, 0, t, tOff, len);
                tOff += len;
            }

            BigInteger k = bitsToInt(t);

            if (k.compareTo(ZERO) > 0 && k.compareTo(n) < 0)
            {
                return k;
            }

            hMac.update(V, 0, V.length);
            hMac.update((byte)0x00);

            hMac.doFinal(K, 0);

            hMac.init(new KeyParameter(K));

            hMac.update(V, 0, V.length);

            hMac.doFinal(V, 0);
        }
    }

    private BigInteger bitsToInt(byte[] t)
    {
        BigInteger v = new BigInteger(1, t);

        if (t.length * 8 > n.bitLength())
        {
            v = v.shiftRight(t.length * 8 - n.bitLength());
        }

        return v;
    }
}
