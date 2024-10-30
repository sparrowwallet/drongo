package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Optional;

public class X25519Key {
    private KeyPair keyPair;
    private final AlgorithmParameterSpec ecSpec;

    public X25519Key() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519");
            this.keyPair = keyPairGenerator.generateKeyPair();
            this.ecSpec = keyPairGenerator.generateKeyPair().getPrivate().getParams();
        } catch(NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public X25519Key(byte[] priv) {
        this();

        X25519PrivateKeyParameters privateKeyParams = new X25519PrivateKeyParameters(priv, 0);
        X25519PublicKeyParameters publicKeyParams = privateKeyParams.generatePublicKey();

        PrivateKey privateKey = new BouncyCastlePrivateKey(privateKeyParams);
        PublicKey publicKey = new BouncyCastlePublicKey(publicKeyParams);
        this.keyPair = new KeyPair(publicKey, privateKey);
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public byte[] getRawPrivateKeyBytes() {
        return Utils.getRawKeyBytesFromPKCS8(keyPair.getPrivate());
    }

    public byte[] getRawPublicKeyBytes() {
        return Utils.getRawKeyBytesFromX509(keyPair.getPublic());
    }

    public class BouncyCastlePrivateKey implements XECPrivateKey {
        private final X25519PrivateKeyParameters privateKeyParams;

        BouncyCastlePrivateKey(X25519PrivateKeyParameters privateKeyParams) {
            this.privateKeyParams = privateKeyParams;
        }

        @Override
        public String getAlgorithm() {
            return "X25519";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return privateKeyParams.getEncoded();
        }

        @Override
        public Optional<byte[]> getScalar() {
            return Optional.of(getEncoded());
        }

        @Override
        public AlgorithmParameterSpec getParams() {
            return ecSpec;
        }
    }

    public class BouncyCastlePublicKey implements XECPublicKey {
        private final X25519PublicKeyParameters publicKeyParams;

        BouncyCastlePublicKey(X25519PublicKeyParameters publicKeyParams) {
            this.publicKeyParams = publicKeyParams;
        }

        @Override
        public String getAlgorithm() {
            return "X25519";
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            try {
                ASN1ObjectIdentifier algOid = new ASN1ObjectIdentifier("1.3.101.110");
                AlgorithmIdentifier algId = new AlgorithmIdentifier(algOid);
                SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, publicKeyParams.getEncoded());
                return spki.getEncoded();
            } catch(IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public BigInteger getU() {
            return new BigInteger(1, publicKeyParams.getEncoded());
        }

        @Override
        public AlgorithmParameterSpec getParams() {
            return ecSpec;
        }
    }
}
