package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ECKeyTest {
    @Test
    public void testGrindLowR() throws MnemonicException {
        String words = "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor";
        DeterministicSeed seed = new DeterministicSeed(words, "", 0, DeterministicSeed.Type.BIP39);
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE);
        wallet.setScriptType(ScriptType.P2PKH);
        Keystore keystore = Keystore.fromSeed(seed, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2PKH, wallet.getKeystores(), 1));

        WalletNode firstReceive = wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
        Address address = firstReceive.getAddress();
        Assertions.assertEquals("14JmU9a7SzieZNEtBnsZo688rt3mGrw6hr", address.toString());
        ECKey privKey = keystore.getKey(firstReceive);

        //1 attempt required for low R
        String signature1 = privKey.signMessage("Test2", ScriptType.P2PKH);
        Assertions.assertEquals("IHra0jSywF1TjIJ5uf7IDECae438cr4o3VmG6Ri7hYlDL+pUEXyUfwLwpiAfUQVqQFLgs6OaX0KsoydpuwRI71o=", signature1);

        //2 attempts required for low R
        String signature2 = privKey.signMessage("Test", ScriptType.P2PKH);
        Assertions.assertEquals("IDgMx1ljPhLHlKUOwnO/jBIgK+K8n8mvDUDROzTgU8gOaPDMs+eYXJpNXXINUx5WpeV605p5uO6B3TzBVcvs478=", signature2);

        //3 attempts required for low R
        String signature3 = privKey.signMessage("Test1", ScriptType.P2PKH);
        Assertions.assertEquals("IEt/v9K95YVFuRtRtWaabPVwWOFv1FSA/e874I8ABgYMbRyVvHhSwLFz0RZuO87ukxDd4TOsRdofQwMEA90LCgI=", signature3);
    }
}
