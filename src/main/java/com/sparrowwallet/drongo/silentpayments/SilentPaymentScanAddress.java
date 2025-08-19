package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.*;

public class SilentPaymentScanAddress extends SilentPaymentAddress {
    public SilentPaymentScanAddress(ECKey scanPrivateKey, ECKey spendPublicKey) {
        super(scanPrivateKey, spendPublicKey);

        if(scanPrivateKey.isPubKeyOnly()) {
            throw new IllegalArgumentException("Scan key must be a private key");
        }
    }

    public static SilentPaymentScanAddress from(DeterministicSeed deterministicSeed, int account) throws MnemonicException {
        Wallet spWallet = new Wallet();
        spWallet.setPolicyType(PolicyType.SINGLE);
        spWallet.setScriptType(ScriptType.P2WPKH);
        Keystore spKeystore = Keystore.fromSeed(deterministicSeed, KeyDerivation.getBip352Derivation(account));
        spWallet.getKeystores().add(spKeystore);
        spWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, spWallet.getKeystores(), 1));

        WalletNode spendNode = new WalletNode(spWallet, "m/0'/0");
        WalletNode scanNode = new WalletNode(spWallet, "m/1'/0");

        return from(spKeystore.getKey(scanNode), ECKey.fromPublicOnly(spKeystore.getKey(spendNode)));
    }

    public static SilentPaymentScanAddress from(ECKey scanPrivateKey, ECKey spendPublicKey) {
        return new SilentPaymentScanAddress(scanPrivateKey, spendPublicKey);
    }
}
