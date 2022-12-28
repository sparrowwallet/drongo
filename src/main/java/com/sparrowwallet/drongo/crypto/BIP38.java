/**
 * Implementation of BIP38 encryption / decryption / key-address generation
 * Based on https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
 *
 * Tips much appreciated: 1EmwBbfgH7BPMoCpcFzyzgAN9Ya7jm8L1Z :)
 *
 * Copyright 2014 Diego Basch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Drongo;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Base58;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static com.sparrowwallet.drongo.crypto.ECKey.CURVE;

public class BIP38 {
    /**
     * Decrypts an encrypted key.
     * @param passphrase
     * @param encryptedKey
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public static DumpedPrivateKey decrypt(String passphrase, String encryptedKey) throws UnsupportedEncodingException, GeneralSecurityException {
        byte[] encryptedKeyBytes = Base58.decodeChecked(encryptedKey);
        DumpedPrivateKey result;
        byte ec = encryptedKeyBytes[1];
        switch (ec) {
            case 0x43: result = decryptEC(passphrase, encryptedKeyBytes);
                break;
            case 0x42: result = decryptNoEC(passphrase, encryptedKeyBytes);
                break;
            default: throw new RuntimeException("Invalid key - second byte is: " + ec);
        }
        return result;
    }

    /**
     * Decrypts a key encrypted with EC multiplication
     * @param passphrase
     * @param encryptedKey
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public static DumpedPrivateKey decryptEC(String passphrase, byte[] encryptedKey) throws UnsupportedEncodingException, GeneralSecurityException {

        byte flagByte = encryptedKey[2];
        byte[] passFactor;
        boolean hasLot = (flagByte & 4) == 4;
        byte[] ownerSalt = Arrays.copyOfRange(encryptedKey, 7, 15 - (flagByte & 4));
        if (!hasLot) {
            passFactor = SCrypt.generate(passphrase.getBytes("UTF8"), ownerSalt, 16384, 8, 8, 32);
        }
        else {
            byte[] preFactor = SCrypt.generate(passphrase.getBytes("UTF8"), ownerSalt, 16384, 8, 8, 32);
            byte[] ownerEntropy = Arrays.copyOfRange(encryptedKey, 7, 15);
            byte[] tmp = Utils.concat(preFactor, ownerEntropy);
            passFactor = Sha256Hash.hashTwice(tmp, 0, 40);
        }

        byte[] addressHash = Arrays.copyOfRange(encryptedKey, 3, 7);
        ECPoint g = CURVE.getG();
        ECPoint p = g.multiply(new BigInteger(1, passFactor));
        byte[] passPoint = p.getEncoded(true);
        byte[] salt = new byte[12];
        byte[] encryptedPart2 = Arrays.copyOfRange(encryptedKey, 23, 39);
        System.arraycopy(addressHash, 0, salt, 0, 4);
        System.arraycopy(encryptedKey, 7, salt, 4, 8);

        byte[] secondKey = SCrypt.generate(passPoint, salt, 1024, 1, 1, 64);
        byte[] derivedHalf1 = Arrays.copyOfRange(secondKey, 0, 32);
        byte[] derivedHalf2 = Arrays.copyOfRange(secondKey, 32, 64);
        byte[] m2 = decryptAES(encryptedPart2, derivedHalf2);

        byte[] encryptedPart1 = new byte[16];
        System.arraycopy(encryptedKey, 15, encryptedPart1, 0, 8);

        byte[] seedB = new byte[24];

        for (int i = 0; i < 16; i++) {
            m2[i] = (byte) (m2[i] ^ derivedHalf1[16 + i]);
        }
        System.arraycopy(m2, 0, encryptedPart1, 8, 8);

        byte[] m1 = decryptAES(encryptedPart1, derivedHalf2);

        for (int i = 0; i < 16; i++) {
            seedB[i] = (byte) (m1[i] ^ derivedHalf1[i]);
        }

        System.arraycopy(m2, 8, seedB, 16, 8);
        byte[] factorB = Sha256Hash.hashTwice(seedB, 0, 24);
        BigInteger n = CURVE.getN();
        BigInteger pk = new BigInteger(1, passFactor).multiply(new BigInteger(1, factorB)).remainder(n);

        ECKey privKey = ECKey.fromPrivate(pk, false);
        return privKey.getPrivateKeyEncoded();
    }

    /**
     * Decrypts a key that was encrypted without EC multiplication.
     * @param passphrase
     * @param encryptedKey
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public static DumpedPrivateKey decryptNoEC(String passphrase, byte[] encryptedKey) throws UnsupportedEncodingException, GeneralSecurityException {

        byte[] addressHash =  Arrays.copyOfRange(encryptedKey, 3, 7);
        byte[] scryptKey = SCrypt.generate(passphrase.getBytes("UTF8"), addressHash, 16384, 8, 8, 64);
        byte[] derivedHalf1 = Arrays.copyOfRange(scryptKey, 0, 32);
        byte[] derivedHalf2 = Arrays.copyOfRange(scryptKey, 32, 64);

        byte[] encryptedHalf1 = Arrays.copyOfRange(encryptedKey, 7, 23);
        byte[] encryptedHalf2 = Arrays.copyOfRange(encryptedKey, 23, 39);
        byte[] k1 = decryptAES(encryptedHalf1, derivedHalf2);
        byte[] k2 = decryptAES(encryptedHalf2, derivedHalf2);
        byte[] keyBytes = new byte[32];
        for (int i = 0; i < 16; i++) {
            keyBytes[i] = (byte) (k1[i] ^ derivedHalf1[i]);
            keyBytes[i + 16] = (byte) (k2[i] ^ derivedHalf1[i + 16]);
        }

        boolean compressed = (encryptedKey[2] & (byte) 0x20) == 0x20;
        ECKey k = new ECKey(new BigInteger(1, keyBytes), null, compressed);
        return k.getPrivateKeyEncoded();
    }

    /**
     * Decrypts ciphertext with AES
     * @param ciphertext
     * @param key
     * @throws GeneralSecurityException
     */
    public static byte[] decryptAES(byte[] ciphertext, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", Drongo.getProvider());
        SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return cipher.doFinal(ciphertext);
    }
}
