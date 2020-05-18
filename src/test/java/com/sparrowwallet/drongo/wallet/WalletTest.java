package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.crypto.Argon2KeyDeriver;
import com.sparrowwallet.drongo.crypto.Key;
import com.sparrowwallet.drongo.crypto.KeyDeriver;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
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
}
