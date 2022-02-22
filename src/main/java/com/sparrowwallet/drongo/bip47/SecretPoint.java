package com.sparrowwallet.drongo.bip47;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class SecretPoint {
    private static final ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
    private static final String KEY_PROVIDER = "BC";

    private final PrivateKey privKey;
    private final PublicKey pubKey;
    private final KeyFactory kf;

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public SecretPoint(byte[] dataPrv, byte[] dataPub) throws InvalidKeySpecException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        kf = KeyFactory.getInstance("ECDH", KEY_PROVIDER);
        privKey = loadPrivateKey(dataPrv);
        pubKey = loadPublicKey(dataPub);
    }

    public byte[] ECDHSecretAsBytes() throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        return ECDHSecret().getEncoded();
    }

    private SecretKey ECDHSecret() throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", KEY_PROVIDER);
        ka.init(privKey);
        ka.doPhase(pubKey, true);
        return ka.generateSecret("AES");
    }

    private PublicKey loadPublicKey(byte[] data) throws InvalidKeySpecException {
        ECPublicKeySpec pubKey = new ECPublicKeySpec(params.getCurve().decodePoint(data), params);
        return kf.generatePublic(pubKey);
    }

    private PrivateKey loadPrivateKey(byte[] data) throws InvalidKeySpecException {
        ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(1, data), params);
        return kf.generatePrivate(prvkey);
    }
}

