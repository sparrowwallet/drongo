package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SignatureDecodeException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.FixedPointUtil;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.Objects;

/**
 * <p>Represents an elliptic curve public and (optionally) private key, usable for digital signatures but not encryption.
 * Creating a new ECKey with the empty constructor will generate a new random keypair. Other static methods can be used
 * when you already have the public or private parts. If you create a key with only the public part, you can check
 * signatures but not create them.</p>
 *
 * <p>ECKey also provides access to Bitcoin Core compatible text message signing, as accessible via the UI or JSON-RPC.
 * This is slightly different to signing raw bytes - if you want to sign your own data and it won't be exposed as
 * text to people, you don't want to use this. If in doubt, ask on the mailing list.</p>
 *
 * <p>The ECDSA algorithm supports <i>key recovery</i> in which a signature plus a couple of discriminator bits can
 * be reversed to find the public key used to calculate it. This can be convenient when you have a message and a
 * signature and want to find out who signed it, rather than requiring the user to provide the expected identity.</p>
 *
 * <p>This class supports a variety of serialization forms. The methods that accept/return byte arrays serialize
 * private keys as raw byte arrays and public keys using the SEC standard byte encoding for public keys. Signatures
 * are encoded using ASN.1/DER inside the Bitcoin protocol.</p>
 *
 * <p>A key can be <i>compressed</i> or <i>uncompressed</i>. This refers to whether the public key is represented
 * when encoded into bytes as an (x, y) coordinate on the elliptic curve, or whether it's represented as just an X
 * co-ordinate and an extra byte that carries a sign bit. With the latter form the Y coordinate can be calculated
 * dynamically, however, <b>because the binary serialization is different the address of a key changes if its
 * compression status is changed</b>. If you deviate from the defaults it's important to understand this: money sent
 * to a compressed version of the key will have a different address to the same key in uncompressed form. Whether
 * a public key is compressed or not is recorded in the SEC binary serialisation format, and preserved in a flag in
 * this class so round-tripping preserves state. Unless you're working with old software or doing unusual things, you
 * can usually ignore the compressed/uncompressed distinction.</p>
 */
public class ECKey implements EncryptableItem {
    private static final Logger log = LoggerFactory.getLogger(ECKey.class);

    /** Sorts oldest keys first, newest last. */
    public static final Comparator<ECKey> AGE_COMPARATOR = new Comparator<ECKey>() {

        @Override
        public int compare(ECKey k1, ECKey k2) {
            if (k1.creationTimeSeconds == k2.creationTimeSeconds)
                return 0;
            else
                return k1.creationTimeSeconds > k2.creationTimeSeconds ? 1 : -1;
        }
    };

    // The parameters of the secp256k1 curve that Bitcoin uses.
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

    /** The parameters of the secp256k1 curve that Bitcoin uses. */
    public static final ECDomainParameters CURVE;

    /**
     * Equal to CURVE.getN().shiftRight(1), used for canonicalising the S value of a signature. If you aren't
     * sure what this is about, you can ignore it.
     */
    public static final BigInteger HALF_CURVE_ORDER;

    private static final SecureRandom secureRandom;

    static {
        // Tell Bouncy Castle to precompute data that's needed during secp256k1 calculations.
        FixedPointUtil.precompute(CURVE_PARAMS.getG());
        CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(),
                CURVE_PARAMS.getH());
        HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);
        secureRandom = new SecureRandom();
    }

    // The two parts of the key. If "pub" is set but not "priv", we can only verify signatures, not make them.
    protected final BigInteger priv;
    protected final LazyECPoint pub;

    // Creation time of the key in seconds since the epoch, or zero if the key was deserialized from a version that did
    // not have this field.
    protected long creationTimeSeconds;

    protected KeyCrypter keyCrypter;
    protected EncryptedData encryptedPrivateKey;

    private byte[] pubKeyHash;

    /**
     * Generates an entirely new keypair. Point compression is used so the resulting public key will be 33 bytes
     * (32 for the co-ordinate and 1 byte to represent the y bit).
     */
    public ECKey() {
        this(secureRandom);
    }

    /**
     * Generates an entirely new keypair with the given {@link SecureRandom} object. Point compression is used so the
     * resulting public key will be 33 bytes (32 for the co-ordinate and 1 byte to represent the y bit).
     */
    public ECKey(SecureRandom secureRandom) {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(CURVE, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();
        priv = privParams.getD();
        pub = getPointWithCompression(pubParams.getQ(), true);
    }

    protected ECKey(BigInteger priv, ECPoint pub, boolean compressed) {
        this(priv, getPointWithCompression(pub, compressed));
    }

    protected ECKey(BigInteger priv, LazyECPoint pub) {
        if(priv != null) {
            if(priv.equals(BigInteger.ZERO) || priv.equals(BigInteger.ONE)) {
                throw new IllegalArgumentException("Private key is illegal: " + priv);
            }
        }

        if(pub == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }

        this.priv = priv;
        this.pub = pub;
    }

    /**
     * Constructs a key that has an encrypted private component. The given object wraps encrypted bytes and an
     * initialization vector. Note that the key will not be decrypted during this call: the returned ECKey is
     * unusable for signing unless a decryption key is supplied.
     */
    public static ECKey fromEncrypted(EncryptedData encryptedPrivateKey, KeyCrypter crypter, byte[] pubKey) {
        ECKey key = fromPublicOnly(pubKey);
        key.encryptedPrivateKey = encryptedPrivateKey;
        key.keyCrypter = crypter;
        return key;
    }

    /**
     * Utility for compressing an elliptic curve point. Returns the same point if it's already compressed.
     * See the ECKey class docs for a discussion of point compression.
     */
    public static LazyECPoint compressPoint(LazyECPoint point) {
        return point.isCompressed() ? point : getPointWithCompression(point.get(), true);
    }

    /**
     * Utility for decompressing an elliptic curve point. Returns the same point if it's already uncompressed.
     * See the ECKey class docs for a discussion of point compression.
     */
    public static LazyECPoint decompressPoint(LazyECPoint point) {
        return !point.isCompressed() ? point : getPointWithCompression(point.get(), false);
    }

    private static LazyECPoint getPointWithCompression(ECPoint point, boolean compressed) {
        return new LazyECPoint(point, compressed);
    }

    /**
     * Construct an ECKey from an ASN.1 encoded private key. These are produced by OpenSSL and stored by Bitcoin
     * Core in its wallet. Note that this is slow because it requires an EC point multiply.
     */
    public static ECKey fromASN1(byte[] asn1privkey) {
        return extractKeyFromASN1(asn1privkey);
    }

    /**
     * Creates an ECKey given the private key only. The public key is calculated from it (this is slow). The resulting
     * public key is compressed.
     */
    public static ECKey fromPrivate(BigInteger privKey) {
        return fromPrivate(privKey, true);
    }

    /**
     * Creates an ECKey given the private key only. The public key is calculated from it (this is slow).
     * @param compressed Determines whether the resulting ECKey will use a compressed encoding for the public key.
     */
    public static ECKey fromPrivate(BigInteger privKey, boolean compressed) {
        ECPoint point = publicPointFromPrivate(privKey);
        return new ECKey(privKey, getPointWithCompression(point, compressed));
    }

    /**
     * Creates an ECKey given the private key only. The public key is calculated from it (this is slow). The resulting
     * public key is compressed.
     */
    public static ECKey fromPrivate(byte[] privKeyBytes) {
        return fromPrivate(new BigInteger(1, privKeyBytes));
    }

    /**
     * Creates an ECKey given the private key only. The public key is calculated from it (this is slow).
     * @param compressed Determines whether the resulting ECKey will use a compressed encoding for the public key.
     */
    public static ECKey fromPrivate(byte[] privKeyBytes, boolean compressed) {
        return fromPrivate(new BigInteger(1, privKeyBytes), compressed);
    }

    /**
     * Creates an ECKey that cannot be used for signing, only verifying signatures, from the given point.
     * @param compressed Determines whether the resulting ECKey will use a compressed encoding for the public key.
     */
    public static ECKey fromPublicOnly(ECPoint pub, boolean compressed) {
        return new ECKey(null, pub, compressed);
    }

    /**
     * Creates an ECKey that cannot be used for signing, only verifying signatures, from the given encoded point.
     * The compression state of pub will be preserved.
     */
    public static ECKey fromPublicOnly(byte[] pub) {
        return new ECKey(null, new LazyECPoint(CURVE.getCurve(), pub));
    }

    public static ECKey fromPublicOnly(ECKey key) {
        return fromPublicOnly(key.getPubKeyPoint(), key.isCompressed());
    }

    /**
     * Returns true if this key doesn't have unencrypted access to private key bytes. This may be because it was never
     * given any private key bytes to begin with (a watching key), or because the key is encrypted.
     */
    public boolean isPubKeyOnly() {
        return priv == null;
    }

    /**
     * Returns true if this key has unencrypted access to private key bytes. Does the opposite of
     * {@link #isPubKeyOnly()}.
     */
    public boolean hasPrivKey() {
        return priv != null;
    }

    /** Returns true if this key is watch only, meaning it has a public key but no private key. */
    public boolean isWatching() {
        return isPubKeyOnly() && !isEncrypted();
    }

    /**
     * Output this ECKey as an ASN.1 encoded private key, as understood by OpenSSL or used by Bitcoin Core
     * in its wallet storage format.
     * @throws MissingPrivateKeyException if the private key is missing or encrypted.
     */
    public byte[] toASN1() {
        try {
            byte[] privKeyBytes = getPrivKeyBytes();
            ByteArrayOutputStream baos = new ByteArrayOutputStream(400);

            // ASN1_SEQUENCE(EC_PRIVATEKEY) = {
            //   ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
            //   ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
            //   ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
            //   ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
            // } ASN1_SEQUENCE_END(EC_PRIVATEKEY)
            DERSequenceGenerator seq = new DERSequenceGenerator(baos);
            seq.addObject(new ASN1Integer(1)); // version
            seq.addObject(new DEROctetString(privKeyBytes));
            seq.addObject(new DERTaggedObject(0, CURVE_PARAMS.toASN1Primitive()));
            seq.addObject(new DERTaggedObject(1, new DERBitString(getPubKey())));
            seq.close();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen, writing to memory stream.
        }
    }

    /**
     * Returns public key bytes from the given private key. To convert a byte array into a BigInteger,
     * use {@code new BigInteger(1, bytes);}
     */
    public static byte[] publicKeyFromPrivate(BigInteger privKey, boolean compressed) {
        ECPoint point = publicPointFromPrivate(privKey);
        return point.getEncoded(compressed);
    }

    /**
     * Returns public key point from the given private key. To convert a byte array into a BigInteger,
     * use {@code new BigInteger(1, bytes);}
     */
    public static ECPoint publicPointFromPrivate(BigInteger privKey) {
        /*
         * TODO: FixedPointCombMultiplier currently doesn't support scalars longer than the group order,
         * but that could change in future versions.
         */
        if (privKey.bitLength() > CURVE.getN().bitLength()) {
            privKey = privKey.mod(CURVE.getN());
        }
        return new FixedPointCombMultiplier().multiply(CURVE.getG(), privKey);
    }

    /** Gets the hash160 form of the public key (as seen in addresses). */
    public byte[] getPubKeyHash() {
        if (pubKeyHash == null)
            pubKeyHash = Utils.sha256hash160(this.pub.getEncoded());
        return pubKeyHash;
    }

    /**
     * Gets the raw public key value. This appears in transaction scriptSigs. Note that this is <b>not</b> the same
     * as the pubKeyHash/address.
     */
    public byte[] getPubKey() {
        return pub.getEncoded();
    }

    /** Gets the public key in the form of an elliptic curve point object from Bouncy Castle. */
    public ECPoint getPubKeyPoint() {
        return pub.get();
    }

    /**
     * Gets the private key in the form of an integer field element. The public key is derived by performing EC
     * point addition this number of times (i.e. point multiplying).
     *
     * @throws java.lang.IllegalStateException if the private key bytes are not available.
     */
    public BigInteger getPrivKey() {
        if (priv == null) {
            throw new MissingPrivateKeyException();
        }

        return priv;
    }

    /**
     * Returns whether this key is using the compressed form or not. Compressed pubkeys are only 33 bytes, not 64.
     */
    public boolean isCompressed() {
        return pub.isCompressed();
    }

    /**
     * Groups the two components that make up a signature, and provides a way to encode to DER form, which is
     * how ECDSA signatures are represented when embedded in other data structures in the Bitcoin protocol. The raw
     * components can be useful for doing further EC maths on them.
     */
    public static class ECDSASignature {
        /** The two components of the signature. */
        public final BigInteger r, s;

        /**
         * Constructs a signature with the given components. Does NOT automatically canonicalise the signature.
         */
        public ECDSASignature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }

        /**
         * Returns true if the S component is "low", that means it is below {@link ECKey#HALF_CURVE_ORDER}. See <a
         * href="https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures">BIP62</a>.
         */
        public boolean isCanonical() {
            return s.compareTo(HALF_CURVE_ORDER) <= 0;
        }

        /**
         * Will automatically adjust the S component to be less than or equal to half the curve order, if necessary.
         * This is required because for every signature (r,s) the signature (r, -s (mod N)) is a valid signature of
         * the same message. However, we dislike the ability to modify the bits of a Bitcoin transaction after it's
         * been signed, as that violates various assumed invariants. Thus in future only one of those forms will be
         * considered legal and the other will be banned.
         */
        public ECDSASignature toCanonicalised() {
            if (!isCanonical()) {
                // The order of the curve is the number of valid points that exist on that curve. If S is in the upper
                // half of the number of valid points, then bring it back to the lower half. Otherwise, imagine that
                //    N = 10
                //    s = 8, so (-8 % 10 == 2) thus both (r, 8) and (r, 2) are valid solutions.
                //    10 - 8 == 2, giving us always the latter solution, which is canonical.
                return new ECDSASignature(r, CURVE.getN().subtract(s));
            } else {
                return this;
            }
        }

        /**
         * DER is an international standard for serializing data structures which is widely used in cryptography.
         * It's somewhat like protocol buffers but less convenient. This method returns a standard DER encoding
         * of the signature, as recognized by OpenSSL and other libraries.
         */
        public byte[] encodeToDER() {
            try {
                return derByteStream().toByteArray();
            } catch (IOException e) {
                throw new RuntimeException(e);  // Cannot happen.
            }
        }

        /**
         * @throws SignatureDecodeException if the signature is unparseable in some way.
         */
        public static ECDSASignature decodeFromDER(byte[] bytes) throws SignatureDecodeException {
            ASN1InputStream decoder = null;
            try {
                // BouncyCastle by default is strict about parsing ASN.1 integers. We relax this check, because some
                // Bitcoin signatures would not parse.
                Properties.setThreadOverride("org.bouncycastle.asn1.allow_unsafe_integer", true);
                decoder = new ASN1InputStream(bytes);
                final ASN1Primitive seqObj = decoder.readObject();
                if (seqObj == null)
                    throw new SignatureDecodeException("Reached past end of ASN.1 stream.");
                if (!(seqObj instanceof DLSequence))
                    throw new SignatureDecodeException("Read unexpected class: " + seqObj.getClass().getName());
                final DLSequence seq = (DLSequence) seqObj;
                ASN1Integer r, s;
                try {
                    r = (ASN1Integer) seq.getObjectAt(0);
                    s = (ASN1Integer) seq.getObjectAt(1);
                } catch (ClassCastException e) {
                    throw new SignatureDecodeException(e);
                }
                // OpenSSL deviates from the DER spec by interpreting these values as unsigned, though they should not be
                // Thus, we always use the positive versions. See: http://r6.ca/blog/20111119T211504Z.html
                return new ECDSASignature(r.getPositiveValue(), s.getPositiveValue());
            } catch (IOException e) {
                throw new SignatureDecodeException(e);
            } finally {
                if (decoder != null)
                    try { decoder.close(); } catch (IOException x) {}
                Properties.removeThreadOverride("org.bouncycastle.asn1.allow_unsafe_integer");
            }
        }

        protected ByteArrayOutputStream derByteStream() throws IOException {
            // Usually 70-72 bytes.
            ByteArrayOutputStream bos = new ByteArrayOutputStream(72);
            DERSequenceGenerator seq = new DERSequenceGenerator(bos);
            seq.addObject(new ASN1Integer(r));
            seq.addObject(new ASN1Integer(s));
            seq.close();
            return bos;
        }

        protected boolean hasLowR() {
            return r.toByteArray().length <= 32;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ECDSASignature other = (ECDSASignature) o;
            return r.equals(other.r) && s.equals(other.s);
        }

        @Override
        public int hashCode() {
            return Objects.hash(r, s);
        }
    }

    /**
     * Signs the given hash and returns the R and S components as BigIntegers. In the Bitcoin protocol, they are
     * usually encoded using ASN.1 format, so you want {@link ECKey.ECDSASignature#toASN1()}
     * instead. However sometimes the independent components can be useful, for instance, if you're going to do
     * further EC maths on them.
     * @throws KeyCrypterException if this ECKey doesn't have a private part.
     */
    public ECDSASignature sign(Sha256Hash input) throws KeyCrypterException {
        return sign(input, null);
    }

    /**
     * Signs the given hash and returns the R and S components as BigIntegers. In the Bitcoin protocol, they are
     * usually encoded using DER format, so you want {@link ECKey.ECDSASignature#encodeToDER()}
     * instead. However sometimes the independent components can be useful, for instance, if you're doing to do further
     * EC maths on them.
     *
     * @param aesKey The AES key to use for decryption of the private key. If null then no decryption is required.
     * @throws KeyCrypterException if there's something wrong with aesKey.
     * @throws ECKey.MissingPrivateKeyException if this key cannot sign because it's pubkey only.
     */
    public ECDSASignature sign(Sha256Hash input, Key aesKey) throws KeyCrypterException {
        KeyCrypter crypter = getKeyCrypter();
        if (crypter != null) {
            if (aesKey == null) {
                throw new KeyIsEncryptedException();
            }
            return decrypt(aesKey).sign(input);
        } else {
            // No decryption of private key required.
            if (priv == null) {
                throw new MissingPrivateKeyException();
            }
        }
        return doSign(input, priv);
    }

    protected ECDSASignature doSign(Sha256Hash input, BigInteger privateKeyForSigning) {
        if(privateKeyForSigning == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }

        ECDSASignature signature;
        int counter = 0;
        do {
            ECDSASigner signer = new ECDSASigner(new HMacDSANonceKCalculator(new SHA256Digest(), counter));
            ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKeyForSigning, CURVE);
            signer.init(true, privKey);
            BigInteger[] components = signer.generateSignature(input.getBytes());
            signature = new ECDSASignature(components[0], components[1]).toCanonicalised();
            counter++;
        } while(!signature.hasLowR());

        return signature;
    }

    /**
     * <p>Verifies the given ECDSA signature against the message bytes using the public key bytes.</p>
     *
     * <p>When using native ECDSA verification, data must be 32 bytes, and no element may be
     * larger than 520 bytes.</p>
     *
     * @param data      Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     * @param pub       The public key bytes to use.
     */
    public static boolean verify(byte[] data, ECDSASignature signature, byte[] pub) {
        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(CURVE.getCurve().decodePoint(pub), CURVE);
        signer.init(false, params);
        try {
            return signer.verifySignature(data, signature.r, signature.s);
        } catch (NullPointerException e) {
            // Bouncy Castle contains a bug that can cause NPEs given specially crafted signatures. Those signatures
            // are inherently invalid/attack sigs so we just fail them here rather than crash the thread.
            log.error("Caught NPE inside bouncy castle", e);
            return false;
        }
    }

    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key.
     *
     * @param data      Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     * @param pub       The public key bytes to use.
     * @throws SignatureDecodeException if the signature is unparseable in some way.
     */
    public static boolean verify(byte[] data, byte[] signature, byte[] pub) throws SignatureDecodeException {
        return verify(data, ECDSASignature.decodeFromDER(signature), pub);
    }

    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key.
     *
     * @param hash      Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     * @throws SignatureDecodeException if the signature is unparseable in some way.
     */
    public boolean verify(byte[] hash, byte[] signature) throws SignatureDecodeException {
        return ECKey.verify(hash, signature, getPubKey());
    }

    /**
     * Verifies the given R/S pair (signature) against a hash using the public key.
     */
    public boolean verify(Sha256Hash sigHash, ECDSASignature signature) {
        return ECKey.verify(sigHash.getBytes(), signature, getPubKey());
    }

    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key, and throws an exception
     * if the signature doesn't match
     * @throws SignatureDecodeException if the signature is unparseable in some way.
     * @throws java.security.SignatureException if the signature does not match.
     */
    public void verifyOrThrow(byte[] hash, byte[] signature) throws SignatureDecodeException, SignatureException {
        if (!verify(hash, signature)) {
            throw new SignatureException();
        }
    }

    /**
     * Verifies the given R/S pair (signature) against a hash using the public key, and throws an exception
     * if the signature doesn't match
     * @throws java.security.SignatureException if the signature does not match.
     */
    public void verifyOrThrow(Sha256Hash sigHash, ECDSASignature signature) throws SignatureException {
        if (!ECKey.verify(sigHash.getBytes(), signature, getPubKey())) {
            throw new SignatureException();
        }
    }

    /**
     * Returns true if the given pubkey is canonical, i.e. the correct length taking into account compression.
     */
    public static boolean isPubKeyCanonical(byte[] pubkey) {
        if (pubkey.length < 33)
            return false;
        if (pubkey[0] == 0x04) {
            // Uncompressed pubkey
            if (pubkey.length != 65)
                return false;
        } else if (pubkey[0] == 0x02 || pubkey[0] == 0x03) {
            // Compressed pubkey
            if (pubkey.length != 33)
                return false;
        } else
            return false;
        return true;
    }

    /**
     * Returns true if the given pubkey is in its compressed form.
     */
    public static boolean isPubKeyCompressed(byte[] encoded) {
        if (encoded.length == 33 && (encoded[0] == 0x02 || encoded[0] == 0x03))
            return true;
        else if (encoded.length == 65 && encoded[0] == 0x04)
            return false;
        else
            throw new IllegalArgumentException(Hex.toHexString(encoded));
    }

    private static ECKey extractKeyFromASN1(byte[] asn1privkey) {
        // To understand this code, see the definition of the ASN.1 format for EC private keys in the OpenSSL source
        // code in ec_asn1.c:
        //
        // ASN1_SEQUENCE(EC_PRIVATEKEY) = {
        //   ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
        //   ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
        //   ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
        //   ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
        // } ASN1_SEQUENCE_END(EC_PRIVATEKEY)
        //
        try {
            ASN1InputStream decoder = new ASN1InputStream(asn1privkey);
            DLSequence seq = (DLSequence)decoder.readObject();
            if(decoder.readObject() != null) {
                throw new IllegalArgumentException("Input contains extra bytes");
            }
            decoder.close();

            if(seq.size() != 4) {
                throw new IllegalArgumentException("Input does not appear to be an ASN.1 OpenSSL EC private key");
            }

            if(!((ASN1Integer) seq.getObjectAt(0)).getValue().equals(BigInteger.ONE)) {
                throw new IllegalArgumentException("Input is of wrong version");
            }

            byte[] privbits = ((ASN1OctetString) seq.getObjectAt(1)).getOctets();
            BigInteger privkey = new BigInteger(1, privbits);

            ASN1TaggedObject pubkey = (ASN1TaggedObject) seq.getObjectAt(3);
            if(pubkey.getTagNo() != 1) {
                throw new IllegalArgumentException("Input has 'publicKey' with bad tag number");
            }

            byte[] pubbits = ((DERBitString)pubkey.getObject()).getBytes();
            if(pubbits.length != 33 && pubbits.length != 65) {
                throw new IllegalArgumentException("Input has 'publicKey' with invalid length");
            };

            int encoding = pubbits[0] & 0xFF;
            // Only allow compressed(2,3) and uncompressed(4), not infinity(0) or hybrid(6,7)
            if(encoding < 2 || encoding > 4) {
                throw new IllegalArgumentException("Input has 'publicKey' with invalid encoding");
            }

            // Now sanity check to ensure the pubkey bytes match the privkey.
            boolean compressed = isPubKeyCompressed(pubbits);
            ECKey key = new ECKey(privkey, null, compressed);
            if(!Arrays.equals(key.getPubKey(), pubbits)) {
                throw new IllegalArgumentException("Public key in ASN.1 structure does not match private key.");
            }

            return key;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen, reading from memory stream.
        }
    }

    /**
     * Returns a 32 byte array containing the private key.
     * @throws MissingPrivateKeyException if the private key bytes are missing/encrypted.
     */
    public byte[] getPrivKeyBytes() {
        return Utils.bigIntegerToBytes(getPrivKey(), 32);
    }

    public void clear() {
        for(int i = 0; i < priv.bitLength(); i++) {
            priv.clearBit(i);
        }
    }

    /**
     * Returns the creation time of this key or zero if the key was deserialized from a version that did not store
     * that data.
     */
    @Override
    public long getCreationTimeSeconds() {
        return creationTimeSeconds;
    }

    /**
     * Sets the creation time of this key. Zero is a convention to mean "unavailable". This method can be useful when
     * you have a raw key you are importing from somewhere else.
     */
    public void setCreationTimeSeconds(long newCreationTimeSeconds) {
        if (newCreationTimeSeconds < 0) {
            throw new IllegalArgumentException("Cannot set creation time to negative value: " + newCreationTimeSeconds);
        }
        creationTimeSeconds = newCreationTimeSeconds;
    }

    /**
     * Create an encrypted private key with the keyCrypter and the AES key supplied.
     * This method returns a new encrypted key and leaves the original unchanged.
     *
     * @param keyCrypter The keyCrypter that specifies exactly how the encrypted bytes are created.
     * @param aesKey The Key with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached as it is slow to create).
     * @return encryptedKey
     */
    public ECKey encrypt(KeyCrypter keyCrypter, Key aesKey) throws KeyCrypterException {
        if(keyCrypter == null) {
            throw new KeyCrypterException("Keycrypter cannot be null");
        }

        final byte[] privKeyBytes = getPrivKeyBytes();
        EncryptedData encryptedPrivateKey = keyCrypter.encrypt(privKeyBytes, null, aesKey);
        ECKey result = ECKey.fromEncrypted(encryptedPrivateKey, keyCrypter, getPubKey());
        result.setCreationTimeSeconds(creationTimeSeconds);
        return result;
    }

    /**
     * Create a decrypted private key with the keyCrypter and AES key supplied. Note that if the aesKey is wrong, this
     * has some chance of throwing KeyCrypterException due to the corrupted padding that will result, but it can also
     * just yield a garbage key.
     *
     * @param keyCrypter The keyCrypter that specifies exactly how the decrypted bytes are created.
     * @param aesKey The Key with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached).
     */
    public ECKey decrypt(KeyCrypter keyCrypter, Key aesKey) throws KeyCrypterException {
        if(keyCrypter == null) {
            throw new KeyCrypterException("Keycrypter cannot be null");
        }

        // Check that the keyCrypter matches the one used to encrypt the keys, if set.
        if (this.keyCrypter != null && !this.keyCrypter.equals(keyCrypter)) {
            throw new KeyCrypterException("The keyCrypter being used to decrypt the key is different to the one that was used to encrypt it");
        }

        if(encryptedPrivateKey == null) {
            throw new IllegalArgumentException("This key is not encrypted");
        }

        byte[] unencryptedPrivateKey = keyCrypter.decrypt(encryptedPrivateKey, aesKey);
        ECKey key = ECKey.fromPrivate(unencryptedPrivateKey);

        if (!Arrays.equals(key.getPubKey(), getPubKey())) {
            throw new KeyCrypterException("Provided AES key is wrong");
        }

        key.setCreationTimeSeconds(creationTimeSeconds);
        return key;
    }

    /**
     * Create a decrypted private key with AES key. Note that if the AES key is wrong, this
     * has some chance of throwing KeyCrypterException due to the corrupted padding that will result, but it can also
     * just yield a garbage key.
     *
     * @param aesKey The Key with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached).
     */
    public ECKey decrypt(Key aesKey) throws KeyCrypterException {
        final KeyCrypter crypter = getKeyCrypter();
        if (crypter == null) {
            throw new KeyCrypterException("No key crypter available");
        }

        return decrypt(crypter, aesKey);
    }

    /**
     * Creates decrypted private key if needed.
     */
    public ECKey maybeDecrypt(Key aesKey) throws KeyCrypterException {
        return isEncrypted() && aesKey != null ? decrypt(aesKey) : this;
    }

    /**
     * <p>Check that it is possible to decrypt the key with the keyCrypter and that the original key is returned.</p>
     *
     * <p>Because it is a critical failure if the private keys cannot be decrypted successfully (resulting of loss of all
     * bitcoins controlled by the private key) you can use this method to check when you *encrypt* a wallet that
     * it can definitely be decrypted successfully.</p>
     *
     * @return true if the encrypted key can be decrypted back to the original key successfully.
     */
    public static boolean encryptionIsReversible(ECKey originalKey, ECKey encryptedKey, KeyCrypter keyCrypter, Key aesKey) {
        try {
            ECKey rebornUnencryptedKey = encryptedKey.decrypt(keyCrypter, aesKey);
            byte[] originalPrivateKeyBytes = originalKey.getPrivKeyBytes();
            byte[] rebornKeyBytes = rebornUnencryptedKey.getPrivKeyBytes();
            if (!Arrays.equals(originalPrivateKeyBytes, rebornKeyBytes)) {
                log.error("The check that encryption could be reversed failed for {}", originalKey);
                return false;
            }
            return true;
        } catch (KeyCrypterException kce) {
            log.error(kce.getMessage());
            return false;
        }
    }

    /**
     * Indicates whether the private key is encrypted (true) or not (false).
     * A private key is deemed to be encrypted when there is both a KeyCrypter and the encryptedPrivateKey is non-zero.
     */
    @Override
    public boolean isEncrypted() {
        return keyCrypter != null && encryptedPrivateKey != null && encryptedPrivateKey.getEncryptedBytes().length > 0;
    }

    @Override
    public EncryptionType getEncryptionType() {
        return new EncryptionType(EncryptionType.Deriver.SCRYPT, keyCrypter != null ? keyCrypter.getCrypterType() : EncryptionType.Crypter.NONE);
    }

    /**
     * A wrapper for {@link #getPrivKeyBytes()} that returns null if the private key bytes are missing or would have
     * to be derived (for the HD key case).
     */
    @Override
    public byte[] getSecretBytes() {
        if (hasPrivKey()) {
            return getPrivKeyBytes();
        } else {
            return null;
        }
    }

    /** An alias for {@link #getEncryptedPrivateKey()} */
    @Override
    public EncryptedData getEncryptedData() {
        return getEncryptedPrivateKey();
    }

    /**
     * Returns the the encrypted private key bytes and initialisation vector for this ECKey, or null if the ECKey
     * is not encrypted.
     */
    public EncryptedData getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    /**
     * Returns the KeyCrypter that was used to encrypt to encrypt this ECKey. You need this to decrypt the ECKey.
     */
    public KeyCrypter getKeyCrypter() {
        return keyCrypter;
    }

    public static class MissingPrivateKeyException extends RuntimeException {
    }

    public static class KeyIsEncryptedException extends MissingPrivateKeyException {
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ECKey)) return false;
        ECKey other = (ECKey) o;
        return Objects.equals(this.priv, other.priv)
                && Objects.equals(this.pub, other.pub);
    }

    @Override
    public int hashCode() {
        return pub.hashCode();
    }

    @Override
    public String toString() {
        return pub.toString();
    }
}
