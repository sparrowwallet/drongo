package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.bip47.PaymentAddress;
import com.sparrowwallet.drongo.bip47.PaymentCode;
import com.sparrowwallet.drongo.crypto.*;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class Keystore extends Persistable {
    private static final Logger log = LoggerFactory.getLogger(Keystore.class);

    public static final String DEFAULT_LABEL = "Keystore 1";
    public static final int MAX_LABEL_LENGTH = 16;

    private String label;
    private KeystoreSource source = KeystoreSource.SW_WATCH;
    private WalletModel walletModel = WalletModel.SPARROW;
    private KeyDerivation keyDerivation;
    private ExtendedKey extendedPublicKey;
    private PaymentCode externalPaymentCode;
    private MasterPrivateExtendedKey masterPrivateExtendedKey;
    private DeterministicSeed seed;

    //For BIP47 keystores - not persisted but must be unencrypted to generate keys
    private transient ExtendedKey bip47ExtendedPrivateKey;

    //Avoid performing repeated expensive seed derivation checks
    private transient boolean extendedPublicKeyChecked;

    public Keystore() {
        this(DEFAULT_LABEL);
    }

    public Keystore(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public String getBaseLabel() {
        return label.replaceAll(" \\d*$", "");
    }

    public String getScriptName() {
        return label.replace(" ", "");
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public KeystoreSource getSource() {
        return source;
    }

    public void setSource(KeystoreSource source) {
        this.source = source;
    }

    public WalletModel getWalletModel() {
        return walletModel;
    }

    public void setWalletModel(WalletModel walletModel) {
        this.walletModel = walletModel;
    }

    public KeyDerivation getKeyDerivation() {
        return keyDerivation;
    }

    public void setKeyDerivation(KeyDerivation keyDerivation) {
        this.keyDerivation = keyDerivation;
    }

    public ExtendedKey getExtendedPublicKey() {
        return extendedPublicKey;
    }

    public void setExtendedPublicKey(ExtendedKey extendedPublicKey) {
        this.extendedPublicKey = extendedPublicKey;
        this.extendedPublicKeyChecked = false;
    }

    public PaymentCode getExternalPaymentCode() {
        return externalPaymentCode;
    }

    public void setExternalPaymentCode(PaymentCode paymentCode) {
        this.externalPaymentCode = paymentCode;
    }

    public boolean hasMasterPrivateExtendedKey() {
        return masterPrivateExtendedKey != null;
    }

    public MasterPrivateExtendedKey getMasterPrivateExtendedKey() {
        return masterPrivateExtendedKey;
    }

    public void setMasterPrivateExtendedKey(MasterPrivateExtendedKey masterPrivateExtendedKey) {
        this.masterPrivateExtendedKey = masterPrivateExtendedKey;
    }

    public boolean hasSeed() {
        return seed != null;
    }

    public DeterministicSeed getSeed() {
        return seed;
    }

    public void setSeed(DeterministicSeed seed) {
        this.seed = seed;
    }

    public boolean hasMasterPrivateKey() {
        return hasSeed() || hasMasterPrivateExtendedKey();
    }

    public boolean hasPrivateKey() {
        return hasMasterPrivateKey() || (source == KeystoreSource.SW_PAYMENT_CODE && bip47ExtendedPrivateKey != null);
    }

    public boolean needsPassphrase() {
        if(seed != null) {
            return seed.needsPassphrase();
        }

        return false;
    }

    public PaymentCode getPaymentCode() {
        DeterministicKey bip47Key = bip47ExtendedPrivateKey.getKey();
        return new PaymentCode(bip47Key.getPubKey(), bip47Key.getChainCode());
    }

    public ExtendedKey getBip47ExtendedPrivateKey() {
        return bip47ExtendedPrivateKey;
    }

    public void setBip47ExtendedPrivateKey(ExtendedKey bip47ExtendedPrivateKey) {
        this.bip47ExtendedPrivateKey = bip47ExtendedPrivateKey;
    }

    public PaymentAddress getPaymentAddress(KeyPurpose keyPurpose, int index) {
        List<ChildNumber> derivation = keyDerivation.getDerivation();
        ChildNumber derivationStart = keyDerivation.getDerivation().isEmpty() ? ChildNumber.ZERO_HARDENED : keyDerivation.getDerivation().get(derivation.size() - 1);
        DeterministicKey privateKey = bip47ExtendedPrivateKey.getKey(List.of(derivationStart, new ChildNumber(keyPurpose == KeyPurpose.SEND ? 0 : index)));
        return new PaymentAddress(externalPaymentCode, keyPurpose == KeyPurpose.SEND ? index : 0, privateKey.getPrivKeyBytes());
    }

    public DeterministicKey getMasterPrivateKey() throws MnemonicException {
        if(seed == null && masterPrivateExtendedKey == null) {
            throw new IllegalArgumentException("Keystore does not contain a master private key, or seed to derive one from");
        }

        if(seed != null) {
            if(seed.isEncrypted()) {
                throw new IllegalArgumentException("Seed is encrypted");
            }

            return HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes());
        }

        if(masterPrivateExtendedKey.isEncrypted()) {
            throw new IllegalArgumentException("Master private key is encrypted");
        }

        return masterPrivateExtendedKey.getPrivateKey();
    }

    public ExtendedKey getExtendedMasterPrivateKey() throws MnemonicException {
        return new ExtendedKey(getMasterPrivateKey(), new byte[4], ChildNumber.ZERO);
    }

    public ExtendedKey getExtendedMasterPublicKey() throws MnemonicException {
        return new ExtendedKey(getMasterPrivateKey().dropPrivateBytes(), new byte[4], ChildNumber.ZERO);
    }

    public ExtendedKey getExtendedPrivateKey() throws MnemonicException {
        List<ChildNumber> derivation = getKeyDerivation().getDerivation();
        DeterministicKey derivedKey = getExtendedMasterPrivateKey().getKey(derivation);
        ExtendedKey xprv = new ExtendedKey(derivedKey, derivedKey.getParentFingerprint(), derivation.isEmpty() ? ChildNumber.ZERO : derivation.get(derivation.size() - 1));
        //Recreate from xprv string to reset path to single ChildNumber at the derived depth
        return ExtendedKey.fromDescriptor(xprv.toString());
    }

    public ECKey getKey(WalletNode walletNode) throws MnemonicException {
        if(source == KeystoreSource.SW_PAYMENT_CODE) {
            try {
                if(walletNode.getKeyPurpose() != KeyPurpose.RECEIVE) {
                    throw new IllegalArgumentException("Cannot get private key for non-receive chain");
                }

                PaymentAddress paymentAddress = getPaymentAddress(walletNode.getKeyPurpose(), walletNode.getIndex());
                return paymentAddress.getReceiveECKey();
            } catch(IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid payment code " + externalPaymentCode, e);
            } catch(Exception e) {
                log.error("Cannot get receive private key at index " + walletNode.getIndex() + " for payment code " + externalPaymentCode, e);
            }
        }

        ExtendedKey extendedPrivateKey = getExtendedPrivateKey();
        List<ChildNumber> derivation = new ArrayList<>();
        derivation.add(extendedPrivateKey.getKeyChildNumber());
        derivation.addAll(walletNode.getDerivation());
        return extendedPrivateKey.getKey(derivation);
    }

    public ECKey getPubKey(WalletNode walletNode) {
        if(source == KeystoreSource.SW_PAYMENT_CODE) {
            try {
                PaymentAddress paymentAddress = getPaymentAddress(walletNode.getKeyPurpose(), walletNode.getIndex());
                return walletNode.getKeyPurpose() == KeyPurpose.RECEIVE ? ECKey.fromPublicOnly(paymentAddress.getReceiveECKey()) : paymentAddress.getSendECKey();
            } catch(IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid payment code " + externalPaymentCode, e);
            } catch(Exception e) {
                log.error("Cannot get receive private key at index " + walletNode.getIndex() + " for payment code " + externalPaymentCode, e);
            }
        }

        List<ChildNumber> derivation = new ArrayList<>();
        derivation.add(extendedPublicKey.getKeyChildNumber());
        derivation.addAll(walletNode.getDerivation());
        return extendedPublicKey.getKey(derivation);
    }

    public KeyDerivation getDerivation(KeyPurpose keyPurpose, int keyIndex) {
        return getKeyDerivation().extend(keyPurpose.getPathIndex()).extend(new ChildNumber(keyIndex));
    }

    public boolean isValid() {
        try {
            checkKeystore();
        } catch(InvalidKeystoreException e) {
            return false;
        }

        return true;
    }

    public void checkKeystore() throws InvalidKeystoreException {
        if(label == null) {
            throw new InvalidKeystoreException("No label specified");
        }

        if(source == null) {
            throw new InvalidKeystoreException("No source specified");
        }

        if(walletModel == null) {
            throw new InvalidKeystoreException("No wallet model specified");
        }

        if(keyDerivation == null) {
            throw new InvalidKeystoreException("No key derivation specified");
        }

        if(extendedPublicKey == null) {
            throw new InvalidKeystoreException("No extended public key specified");
        }

        if(label.isEmpty()) {
            throw new InvalidKeystoreException("Label too short");
        }

        if(label.replace(" ", "").length() > MAX_LABEL_LENGTH) {
            throw new InvalidKeystoreException("Label too long");
        }

        if(keyDerivation.getDerivationPath() == null || keyDerivation.getDerivationPath().isEmpty() || !KeyDerivation.isValid(keyDerivation.getDerivationPath())) {
            throw new InvalidKeystoreException("Invalid key derivation path of " + keyDerivation.getDerivationPath());
        }

        if(keyDerivation.getMasterFingerprint() == null || keyDerivation.getMasterFingerprint().length() != 8 || !Utils.isHex(keyDerivation.getMasterFingerprint())) {
            throw new InvalidKeystoreException("Invalid master fingerprint of " + keyDerivation.getMasterFingerprint());
        }

        if(source == KeystoreSource.SW_SEED) {
            if(seed == null && masterPrivateExtendedKey == null) {
                throw new InvalidKeystoreException("Source of " + source + " but no seed or master private key is present");
            }

            if(!extendedPublicKeyChecked && ((seed != null && !seed.isEncrypted()) || (masterPrivateExtendedKey != null && !masterPrivateExtendedKey.isEncrypted()))) {
                try {
                    List<ChildNumber> derivation = getKeyDerivation().getDerivation();
                    DeterministicKey derivedKey = getExtendedMasterPrivateKey().getKey(derivation);
                    DeterministicKey derivedKeyPublicOnly = derivedKey.dropPrivateBytes().dropParent();
                    ExtendedKey xpub = new ExtendedKey(derivedKeyPublicOnly, derivedKey.getParentFingerprint(), derivation.isEmpty() ? ChildNumber.ZERO : derivation.get(derivation.size() - 1));
                    if(!xpub.equals(getExtendedPublicKey())) {
                        throw new InvalidKeystoreException("Specified extended public key does not match public key derived from seed");
                    }
                    extendedPublicKeyChecked = true;
                } catch(MnemonicException e) {
                    throw new InvalidKeystoreException("Invalid mnemonic specified for seed", e);
                }
            }
        }

        if(source == KeystoreSource.SW_PAYMENT_CODE) {
            if(externalPaymentCode == null) {
                throw new InvalidKeystoreException("Source of " + source + " but no payment code is present");
            }

            if(bip47ExtendedPrivateKey == null) {
                throw new InvalidKeystoreException("Source of " + source + " but no extended private key is present");
            }
        }
    }

    public Keystore copy() {
        Keystore copy = new Keystore(label);
        copy.setId(getId());
        copy.setSource(source);
        copy.setWalletModel(walletModel);
        if(keyDerivation != null) {
            copy.setKeyDerivation(keyDerivation.copy());
        }
        if(extendedPublicKey != null) {
            copy.setExtendedPublicKey(extendedPublicKey.copy());
        }
        if(masterPrivateExtendedKey != null) {
            copy.setMasterPrivateExtendedKey(masterPrivateExtendedKey.copy());
        }
        if(seed != null) {
            copy.setSeed(seed.copy());
        }
        if(externalPaymentCode != null) {
            copy.setExternalPaymentCode(externalPaymentCode.copy());
        }
        if(bip47ExtendedPrivateKey != null) {
            copy.setBip47ExtendedPrivateKey(bip47ExtendedPrivateKey.copy());
        }
        return copy;
    }

    public static Keystore fromSeed(DeterministicSeed seed, List<ChildNumber> derivation) throws MnemonicException {
        Keystore keystore = new Keystore();
        keystore.setSeed(seed);
        keystore.setLabel(seed.getType().name());
        rederiveKeystoreFromMaster(keystore, derivation);
        return keystore;
    }

    public static Keystore fromMasterPrivateExtendedKey(MasterPrivateExtendedKey masterPrivateExtendedKey, List<ChildNumber> derivation) throws MnemonicException {
        Keystore keystore = new Keystore();
        keystore.setMasterPrivateExtendedKey(masterPrivateExtendedKey);
        keystore.setLabel("Master Key");
        rederiveKeystoreFromMaster(keystore, derivation);
        return keystore;
    }

    private static void rederiveKeystoreFromMaster(Keystore keystore, List<ChildNumber> derivation) throws MnemonicException {
        ExtendedKey xprv = keystore.getExtendedMasterPrivateKey();
        String masterFingerprint = Utils.bytesToHex(xprv.getKey().getFingerprint());
        DeterministicKey derivedKey = xprv.getKey(derivation);
        DeterministicKey derivedKeyPublicOnly = derivedKey.dropPrivateBytes().dropParent();
        ExtendedKey xpub = new ExtendedKey(derivedKeyPublicOnly, derivedKey.getParentFingerprint(), derivation.isEmpty() ? ChildNumber.ZERO : derivation.get(derivation.size() - 1));

        keystore.setSource(KeystoreSource.SW_SEED);
        keystore.setWalletModel(WalletModel.SPARROW);
        keystore.setKeyDerivation(new KeyDerivation(masterFingerprint, KeyDerivation.writePath(derivation)));
        keystore.setExtendedPublicKey(ExtendedKey.fromDescriptor(xpub.toString()));

        int account = ScriptType.getScriptTypesForPolicyType(PolicyType.SINGLE).stream()
                .mapToInt(scriptType -> scriptType.getAccount(keystore.getKeyDerivation().getDerivationPath())).filter(idx -> idx > -1).findFirst().orElse(0);
        List<ChildNumber> bip47Derivation = KeyDerivation.getBip47Derivation(account);
        DeterministicKey bip47Key = xprv.getKey(bip47Derivation);
        ExtendedKey bip47ExtendedPrivateKey = new ExtendedKey(bip47Key, bip47Key.getParentFingerprint(), bip47Derivation.get(bip47Derivation.size() - 1));
        keystore.setBip47ExtendedPrivateKey(ExtendedKey.fromDescriptor(bip47ExtendedPrivateKey.toString()));
    }

    public boolean isEncrypted() {
        return (seed != null && seed.isEncrypted()) || (masterPrivateExtendedKey != null && masterPrivateExtendedKey.isEncrypted());
    }

    public void encrypt(Key key) {
        if(hasSeed() && !seed.isEncrypted()) {
            seed = seed.encrypt(key);
        }
        if(hasMasterPrivateExtendedKey() && !masterPrivateExtendedKey.isEncrypted()) {
            masterPrivateExtendedKey = masterPrivateExtendedKey.encrypt(key);
        }
    }

    public void decrypt(CharSequence password) {
        if(hasSeed() && seed.isEncrypted()) {
            seed = seed.decrypt(password);
        }
        if(hasMasterPrivateExtendedKey() && masterPrivateExtendedKey.isEncrypted()) {
            masterPrivateExtendedKey = masterPrivateExtendedKey.decrypt(password);
        }
    }

    public void decrypt(Key key) {
        if(hasSeed() && seed.isEncrypted()) {
            seed = seed.decrypt(key);
        }
        if(hasMasterPrivateExtendedKey() && masterPrivateExtendedKey.isEncrypted()) {
            masterPrivateExtendedKey = masterPrivateExtendedKey.decrypt(key);
        }
    }

    public void clearPrivate() {
        if(hasSeed()) {
            seed.clear();
        }
        if(hasMasterPrivateExtendedKey()) {
            masterPrivateExtendedKey.clear();
        }
    }
}
