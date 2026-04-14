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
    public SilentPaymentScanAddress(ECKey scanPrivateKey, ECKey spendPublicKey) {
        super(scanPrivateKey, spendPublicKey);

        if(scanPrivateKey.isPubKeyOnly()) {
            throw new IllegalArgumentException("Scan key must be a private key");
        }
    }

    public ECKey getChangeTweakKey() {
        return SilentPaymentUtils.getLabelledTweakKey(getScanKey(), 0);
    }

    public ECKey getLabelledTweakKey(int labelIndex) {
        return SilentPaymentUtils.getLabelledTweakKey(getScanKey(), labelIndex);
    }

    public SilentPaymentScanAddress getChangeAddress() {
        return getLabelledAddress(0);
    }

    public SilentPaymentScanAddress getLabelledAddress(int labelIndex) {
        ECKey labelledSpendKey = SilentPaymentUtils.getLabelledSpendKey(getScanKey(), getSpendKey(), labelIndex);
        return new SilentPaymentScanAddress(getScanKey(), labelledSpendKey);
    }

    public static SilentPaymentScanAddress from(DeterministicSeed deterministicSeed, int account) throws MnemonicException {
        Wallet spWallet = new Wallet();
        spWallet.setPolicyType(PolicyType.SINGLE_HD);
        spWallet.setScriptType(ScriptType.P2WPKH);
        Keystore spKeystore = Keystore.fromSeed(deterministicSeed, KeyDerivation.getBip352Derivation(account));
        spWallet.getKeystores().add(spKeystore);
        spWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, spWallet.getKeystores(), 1));

        WalletNode spendNode = new WalletNode(spWallet, "m/0'/0");
        WalletNode scanNode = new WalletNode(spWallet, "m/1'/0");

        return from(spKeystore.getKey(scanNode), ECKey.fromPublicOnly(spKeystore.getKey(spendNode)));
    }

    public static SilentPaymentScanAddress from(ECKey scanPrivateKey, ECKey spendPublicKey) {
        return new SilentPaymentScanAddress(scanPrivateKey, spendPublicKey);
    }

    public SilentPaymentScanAddress copy() {
        return new SilentPaymentScanAddress(getScanKey(), getSpendKey());
    }

    public String toKeyString() {
        return Bech32.encode(Network.get().getSilentPaymentsKeyHrp(), 0, Bech32.Encoding.BECH32M, toBytes());
    }

    public byte[] toBytes() {
        return Utils.concat(getScanKey().getPrivKeyBytes(), getSpendKey().getPubKey(true));
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
