package com.sparrowwallet.drongo.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

/*
 * Encrypt data according to Electrum ECIES format (also called BIE1)
 */
public class ECIESKeyCrypter implements AsymmetricKeyCrypter {
    private final KeyCrypter aesKeyCrypter = new AESKeyCrypter();

    @Override
    public byte[] decrypt(EncryptedData encryptedBytesToDecode, ECKey key) throws KeyCrypterException {
        return decryptEcies(encryptedBytesToDecode.getEncryptedBytes(), encryptedBytesToDecode.getInitialisationVector(), key);
    }

    public byte[] decryptEcies(byte[] message, byte[] magic, ECKey key) {
        byte[] decoded = Base64.getDecoder().decode(message);
        if(decoded.length < 85) {
            throw new IllegalArgumentException("Ciphertext is too short at " + decoded.length + " bytes");
        }
        byte[] magicFound = Arrays.copyOfRange(decoded, 0, 4);
        byte[] ephemeralPubKeyBytes = Arrays.copyOfRange(decoded, 4, 37);
        byte[] ciphertext = Arrays.copyOfRange(decoded, 37, decoded.length - 32);
        byte[] mac = Arrays.copyOfRange(decoded, decoded.length - 32, decoded.length);

        if(!Arrays.equals(magic, magicFound)) {
            throw new IllegalArgumentException("Invalid ciphertext: invalid magic bytes");
        }

        ECKey ephemeralPubKey = ECKey.fromPublicOnly(ephemeralPubKeyBytes);
        byte[] ecdh_key = ephemeralPubKey.getPubKeyPoint().multiply(key.getPrivKey()).getEncoded(true);
        byte[] hash = sha512(ecdh_key);

        byte[] iv = Arrays.copyOfRange(hash, 0, 16);
        byte[] key_e = Arrays.copyOfRange(hash, 16, 32);
        byte[] key_m = Arrays.copyOfRange(hash, 32, 64);
        byte[] hmacInput = Arrays.copyOfRange(decoded, 0, decoded.length - 32);

        if(!Arrays.equals(mac, hmac256(key_m, hmacInput))) {
            throw new InvalidPasswordException("The password was invalid");
        }

        return aesKeyCrypter.decrypt(new EncryptedData(iv, ciphertext, null, null), new Key(key_e, null, null));
    }

    @Override
    public EncryptedData encrypt(byte[] plainBytes, byte[] initializationVector, ECKey key) throws KeyCrypterException {
        byte[] encryptedBytes = encryptEcies(key, plainBytes, initializationVector);
        return new EncryptedData(initializationVector, encryptedBytes, null, null);
    }

    public byte[] encryptEcies(ECKey key, byte[] message, byte[] magic) {
        ECKey ephemeral = new ECKey();
        byte[] ecdh_key = key.getPubKeyPoint().multiply(ephemeral.getPrivKey()).getEncoded(true);
        byte[] hash = sha512(ecdh_key);

        byte[] iv = Arrays.copyOfRange(hash, 0, 16);
        byte[] key_e = Arrays.copyOfRange(hash, 16, 32);
        byte[] key_m = Arrays.copyOfRange(hash, 32, 64);

        byte[] ciphertext = aesKeyCrypter.encrypt(message, iv, new Key(key_e, null, null)).getEncryptedBytes();
        byte[] encrypted = concat(magic, ephemeral.getPubKey(), ciphertext);
        byte[] result = hmac256(key_m, encrypted);
        return Base64.getEncoder().encode(concat(encrypted, result));
    }

    private byte[] sha512(byte[] input) {
        SHA512Digest digest = new SHA512Digest();
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(input, 0, input.length);
        digest.doFinal(hash, 0);
        return hash;
    }

    private byte[] hmac256(byte[] key, byte[] input) {
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(key));
        byte[] result = new byte[hmac.getMacSize()];
        hmac.update(input, 0, input.length);
        hmac.doFinal(result, 0);
        return result;
    }

    private byte[] concat(byte[] ...bytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            for(byte[] byteArray : bytes) {
                out.write(byteArray);
            }
        } catch (IOException e) {
            //can't happen
        }
        return out.toByteArray();
    }
}
