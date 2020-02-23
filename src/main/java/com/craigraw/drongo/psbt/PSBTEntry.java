package com.craigraw.drongo.psbt;

import com.craigraw.drongo.KeyDerivation;
import com.craigraw.drongo.crypto.ChildNumber;
import org.bouncycastle.util.encoders.Hex;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PSBTEntry {
    private byte[] key = null;
    private byte keyType;
    private byte[] keyData = null;
    private byte[] data = null;

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public byte getKeyType() {
        return keyType;
    }

    public void setKeyType(byte keyType) {
        this.keyType = keyType;
    }

    public byte[] getKeyData() {
        return keyData;
    }

    public void setKeyData(byte[] keyData) {
        this.keyData = keyData;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public static KeyDerivation parseKeyDerivation(byte[] data) {
        String masterFingerprint = getMasterFingerprint(Arrays.copyOfRange(data, 0, 4));
        List<ChildNumber> bip32pathList = readBIP32Derivation(Arrays.copyOfRange(data, 4, data.length));
        String bip32path = KeyDerivation.writePath(bip32pathList);
        return new KeyDerivation(masterFingerprint, bip32path);
    }

    public static String getMasterFingerprint(byte[] data) {
        return Hex.toHexString(data);
    }

    public static List<ChildNumber> readBIP32Derivation(byte[] data) {
        List<ChildNumber> path = new ArrayList<>();

        ByteBuffer bb = ByteBuffer.wrap(data);
        byte[] buf = new byte[4];

        do {
            bb.get(buf);
            reverse(buf);
            ByteBuffer pbuf = ByteBuffer.wrap(buf);
            path.add(new ChildNumber(pbuf.getInt()));
        } while(bb.hasRemaining());

        return path;
    }

    private static void reverse(byte[] array) {
        for (int i = 0; i < array.length / 2; i++) {
            byte temp = array[i];
            array[i] = array[array.length - i - 1];
            array[array.length - i - 1] = temp;
        }
    }

    public void checkOneByteKey() {
        if(this.getKey().length != 1) {
            throw new IllegalStateException("PSBT key type must be one byte");
        }
    }

    public void checkOneBytePlusXpubKey() {
        if(this.getKey().length != 79) {
            throw new IllegalStateException("PSBT key type must be one byte");
        }
    }

    public void checkOneBytePlusPubKey() {
        if(this.getKey().length != 34) {
            throw new IllegalStateException("PSBT key type must be one byte");
        }
    }
}
