package com.sparrowwallet.drongo.bip47;

import com.sparrowwallet.drongo.crypto.ECKey;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class PaymentAddress {
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());

    private final PaymentCode paymentCode;
    private final int index;
    private final byte[] privKey;

    public PaymentAddress(PaymentCode paymentCode, int index, byte[] privKey) {
        this.paymentCode = paymentCode;
        this.index = index;
        this.privKey = privKey;
    }

    public ECKey getSendECKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
        return getSendECKey(getSecretPoint());
    }

    public ECKey getReceiveECKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
        return getReceiveECKey(getSecretPoint());
    }

    public SecretPoint getSharedSecret() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException {
        return sharedSecret();
    }

    public BigInteger getSecretPoint() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
        return secretPoint();
    }

    public ECPoint getECPoint() {
        ECKey ecKey = ECKey.fromPublicOnly(paymentCode.getKey(index).getPubKey());
        return ecKey.getPubKeyPoint();
    }

    public byte[] hashSharedSecret() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(getSharedSecret().ECDHSecretAsBytes());
    }

    private ECPoint get_sG(BigInteger s) {
        return CURVE_PARAMS.getG().multiply(s);
    }

    private ECKey getSendECKey(BigInteger s) throws IllegalStateException {
        ECPoint ecPoint = getECPoint();
        ECPoint sG = get_sG(s);
        return ECKey.fromPublicOnly(ecPoint.add(sG).getEncoded(true));
    }

    private ECKey getReceiveECKey(BigInteger s) {
        BigInteger privKeyValue = ECKey.fromPrivate(privKey).getPrivKey();
        return ECKey.fromPrivate(addSecp256k1(privKeyValue, s));
    }

    private BigInteger addSecp256k1(BigInteger b1, BigInteger b2) {
        BigInteger ret = b1.add(b2);

        if(ret.compareTo(CURVE.getN()) > 0) {
            return ret.mod(CURVE.getN());
        }

        return ret;
    }

    private SecretPoint sharedSecret() throws InvalidKeySpecException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        return new SecretPoint(privKey, paymentCode.getKey(index).getPubKey());
    }

    private boolean isSecp256k1(BigInteger b) {
        return (b.compareTo(BigInteger.ONE) > 0) && (b.compareTo(CURVE.getN()) < 0);
    }

    private BigInteger secretPoint() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NotSecp256k1Exception {
        //
        // convert hash to value 's'
        //
        BigInteger s = new BigInteger(1, hashSharedSecret());
        //
        // check that 's' is on the secp256k1 curve
        //
        if(!isSecp256k1(s)) {
            throw new NotSecp256k1Exception("Secret point not on Secp256k1 curve");
        }

        return s;
    }
}

