package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.crypto.Argon2KeyDeriver;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.crypto.KeyDeriver;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.Assert;
import org.junit.Test;

public class WalletTest {
    @Test
    public void encryptTest() throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        DeterministicSeed seed = new DeterministicSeed(words, "pp", 0, DeterministicSeed.Type.BIP39);
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE);
        wallet.setScriptType(ScriptType.P2PKH);
        Keystore keystore = Keystore.fromSeed(seed, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2PKH, wallet.getKeystores(), 1));

        KeyDeriver keyDeriver = new Argon2KeyDeriver();
        Key key = keyDeriver.deriveKey("pass");
        wallet.encrypt(key);

        wallet.decrypt("pass");
    }

    @Test
    public void makeLabelsUnique() {
        Wallet wallet = new Wallet();
        Keystore keystore1 = new Keystore("BIP39");
        wallet.getKeystores().add(keystore1);

        Keystore keystore2 = new Keystore("BIP39 2");
        wallet.getKeystores().add(keystore2);

        Keystore keystore3 = new Keystore("Coldcard");
        wallet.getKeystores().add(keystore3);

        Keystore keystore4 = new Keystore("Coldcard2");
        wallet.getKeystores().add(keystore4);

        Keystore keystore5 = new Keystore("Coldcard -1");
        wallet.getKeystores().add(keystore5);

        Keystore keystore = new Keystore("BIP39");
        wallet.makeLabelsUnique(keystore);
        Assert.assertEquals("BIP39 3", keystore1.getLabel());
        Assert.assertEquals("BIP39 4", keystore.getLabel());

        Keystore cckeystore = new Keystore("Coldcard");
        wallet.makeLabelsUnique(cckeystore);
        Assert.assertEquals("Coldcard 3", keystore3.getLabel());
        Assert.assertEquals("Coldcard 4", cckeystore.getLabel());
    }
}
