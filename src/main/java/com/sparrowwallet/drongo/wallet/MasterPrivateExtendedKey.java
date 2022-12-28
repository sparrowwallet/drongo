package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.crypto.*;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class MasterPrivateExtendedKey extends Persistable implements EncryptableItem {
    private final byte[] privateKey;
    private final byte[] chainCode;

    private final EncryptedData encryptedKey;

    public MasterPrivateExtendedKey(byte[] privateKey, byte[] chainCode) {
        this.privateKey = privateKey;
        this.chainCode = chainCode;
        this.encryptedKey = null;
    }

    public MasterPrivateExtendedKey(EncryptedData encryptedKey) {
        this.privateKey = null;
        this.chainCode = null;
        this.encryptedKey = encryptedKey;
    }

    public DeterministicKey getPrivateKey() {
        return HDKeyDerivation.createMasterPrivKeyFromBytes(privateKey, chainCode);
    }

    public ExtendedKey getExtendedPrivateKey() {
        return new ExtendedKey(getPrivateKey(), new byte[4], ChildNumber.ZERO);
    }

    @Override
    public boolean isEncrypted() {
        if((privateKey != null || chainCode != null) && encryptedKey != null) {
            throw new IllegalStateException("Cannot be in a encrypted and unencrypted state");
        }

        return encryptedKey != null;
    }

    @Override
    public byte[] getSecretBytes() {
        if(privateKey == null || chainCode == null) {
            throw new IllegalStateException("Cannot get secret bytes for null or encrypted key");
        }

        ByteBuffer byteBuffer = ByteBuffer.allocate(64);
        byteBuffer.put(privateKey);
        byteBuffer.put(chainCode);
        return byteBuffer.array();
    }

    @Override
    public EncryptedData getEncryptedData() {
        return encryptedKey;
    }

    @Override
    public EncryptionType getEncryptionType() {
        return new EncryptionType(EncryptionType.Deriver.ARGON2, EncryptionType.Crypter.AES_CBC_PKCS7);
    }

    @Override
    public long getCreationTimeSeconds() {
        return 0;
    }

    public MasterPrivateExtendedKey encrypt(Key key) {
        if(encryptedKey != null) {
            throw new IllegalArgumentException("Trying to encrypt twice");
        }
        if(privateKey == null || chainCode == null) {
            throw new IllegalArgumentException("Private key data missing so cannot encrypt");
        }

        KeyCrypter keyCrypter = getEncryptionType().getCrypter().getKeyCrypter();
        byte[] secretBytes = getSecretBytes();
        EncryptedData encryptedKeyData = keyCrypter.encrypt(secretBytes, null, key);
        Arrays.fill(secretBytes != null ? secretBytes : new byte[0], (byte)0);

        MasterPrivateExtendedKey mpek = new MasterPrivateExtendedKey(encryptedKeyData);
        mpek.setId(getId());

        return mpek;
    }

    public MasterPrivateExtendedKey decrypt(CharSequence password) {
        if(!isEncrypted()) {
            throw new IllegalStateException("Cannot decrypt unencrypted master private key");
        }

        KeyDeriver keyDeriver = getEncryptionType().getDeriver().getKeyDeriver(encryptedKey.getKeySalt());
        Key key = keyDeriver.deriveKey(password);
        MasterPrivateExtendedKey mpek = decrypt(key);
        mpek.setId(getId());
        key.clear();

        return mpek;
    }

    public MasterPrivateExtendedKey decrypt(Key key) {
        if(!isEncrypted()) {
            throw new IllegalStateException("Cannot decrypt unencrypted master private key");
        }

        KeyCrypter keyCrypter = getEncryptionType().getCrypter().getKeyCrypter();
        byte[] decrypted = keyCrypter.decrypt(encryptedKey, key);
        try {
            MasterPrivateExtendedKey mpek = new MasterPrivateExtendedKey(Arrays.copyOfRange(decrypted, 0, 32), Arrays.copyOfRange(decrypted, 32, 64));
            mpek.setId(getId());
            return mpek;
        } finally {
            Arrays.fill(decrypted, (byte)0);
        }
    }

    public MasterPrivateExtendedKey copy() {
        MasterPrivateExtendedKey copy;
        if(isEncrypted()) {
            copy = new MasterPrivateExtendedKey(encryptedKey.copy());
        } else {
            copy = new MasterPrivateExtendedKey(Arrays.copyOf(privateKey, 32), Arrays.copyOf(chainCode, 32));
        }

        copy.setId(getId());
        return copy;
    }

    public void clear() {
        if(privateKey != null) {
            Arrays.fill(privateKey, (byte)0);
        }
        if(chainCode != null) {
            Arrays.fill(chainCode, (byte)0);
        }
    }

    public MasterPrivateExtendedKey fromXprv(ExtendedKey xprv) {
        return new MasterPrivateExtendedKey(xprv.getKey().getPrivKeyBytes(), xprv.getKey().getChainCode());
    }
}
