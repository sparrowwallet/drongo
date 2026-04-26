package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Bech32;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.*;

import java.util.Arrays;

public class SilentPaymentScanAddress extends SilentPaymentAddress {
    public static final long CHANGE_LABEL_INDEX = 0L;

    public SilentPaymentScanAddress(ECKey scanPrivateKey, ECKey spendPublicKey) {
        super(scanPrivateKey, spendPublicKey);

        if(scanPrivateKey.isPubKeyOnly()) {
            throw new IllegalArgumentException("Scan key must be a private key");
        }
    }

    public ECKey getChangeTweakKey() {
        return SilentPaymentUtils.getLabelledTweakKey(getScanKey(), CHANGE_LABEL_INDEX);
    }

    public ECKey getLabelledTweakKey(long labelIndex) {
        return SilentPaymentUtils.getLabelledTweakKey(getScanKey(), labelIndex);
    }

    public SilentPaymentScanAddress getChangeAddress() {
        return getLabelledAddress(CHANGE_LABEL_INDEX);
    }

    public SilentPaymentScanAddress getLabelledAddress(long labelIndex) {
        ECKey labelledSpendKey = SilentPaymentUtils.getLabelledSpendKey(getScanKey(), getSpendKey(), labelIndex);
        return new SilentPaymentScanAddress(getScanKey(), labelledSpendKey);
    }

    public static SilentPaymentScanAddress from(DeterministicSeed deterministicSeed, int account) throws MnemonicException {
        Wallet spWallet = new Wallet();
        spWallet.setPolicyType(PolicyType.SINGLE_HD);
        spWallet.setScriptType(ScriptType.P2WPKH);
        Keystore spKeystore = Keystore.fromSeed(deterministicSeed, PolicyType.SINGLE_HD, KeyDerivation.getBip352Derivation(account));
        spWallet.getKeystores().add(spKeystore);
        spWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, spWallet.getKeystores(), 1));

        WalletNode spendNode = new WalletNode(spWallet, "m/0'/0");
        WalletNode scanNode = new WalletNode(spWallet, "m/1'/0");

        return from(spKeystore.getKey(scanNode), ECKey.fromPublicOnly(spKeystore.getKey(spendNode)));
    }

    public static SilentPaymentScanAddress from(ECKey scanPrivateKey, ECKey spendPublicKey) {
        return new SilentPaymentScanAddress(scanPrivateKey, spendPublicKey);
    }

    public SilentPaymentAddress getSilentPaymentAddress() {
        return new SilentPaymentAddress(ECKey.fromPublicOnly(getScanKey()), getSpendKey());
    }

    public SilentPaymentScanAddress copy() {
        return new SilentPaymentScanAddress(getScanKey(), getSpendKey());
    }

    public String toKeyString() {
        return Bech32.encode(Network.get().getSilentPaymentsScanKeyHrp(), 0, Bech32.Encoding.BECH32M, toBytes());
    }

    public byte[] toBytes() {
        return Utils.concat(getScanKey().getPrivKeyBytes(), getSpendKey().getPubKey(true));
    }

    public static boolean isValid(String encoded) {
        try {
            fromKeyString(encoded);
        } catch(Exception e) {
            return false;
        }

        return true;
    }

    public static SilentPaymentScanAddress fromKeyString(String encoded) {
        Bech32.Bech32Data data = Bech32.decode(encoded, 1023);
        if(data.encoding != Bech32.Encoding.BECH32M) {
            throw new IllegalArgumentException("Invalid silent payment key encoding");
        }

        int version = data.data[0];
        if(version != 0) {
            throw new UnsupportedOperationException("Unsupported silent payment key version: " + version);
        }

        byte[] payload = Bech32.convertBits(data.data, 1, data.data.length - 1, 5, 8, false);

        String scanHrp = Network.get().getSilentPaymentsScanKeyHrp();
        String spendHrp = Network.get().getSilentPaymentsSpendKeyHrp();
        if(data.hrp.equals(scanHrp)) {
            return fromBytes(payload);
        } else if(data.hrp.equals(spendHrp)) {
            if(payload.length != 64) {
                throw new IllegalArgumentException("Invalid spspend payload length: " + payload.length);
            }
            ECKey scanKey = ECKey.fromPrivate(Arrays.copyOfRange(payload, 0, 32));
            ECKey spendKey = ECKey.fromPublicOnly(ECKey.fromPrivate(Arrays.copyOfRange(payload, 32, 64)).getPubKey());

            return new SilentPaymentScanAddress(scanKey, spendKey);
        } else {
            throw new IllegalArgumentException("Invalid silent payment key HRP: " + data.hrp);
        }
    }

    public static SilentPaymentScanAddress fromBytes(byte[] bytes) {
        if(bytes == null || bytes.length != 65) {
            throw new IllegalArgumentException("Invalid silent payments scan address serialization, must be 65 bytes long");
        }

        ECKey scanKey = ECKey.fromPrivate(Arrays.copyOfRange(bytes, 0, 32));
        ECKey spendKey = ECKey.fromPublicOnly(Arrays.copyOfRange(bytes, 32, 65));

        return new SilentPaymentScanAddress(scanKey, spendKey);
    }
}
