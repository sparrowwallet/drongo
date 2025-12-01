package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

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

    @Test
    void testTweakPrivKeyTestvectorBip341() {
        // test vector (without script path) from BIP341:
        // https://github.com/bitcoin/bips/blob/9a30c28574e62e26da77f14e33eb698b81268887/bip-0341/wallet-test-vectors.json#L278
        String internalPrivKeyHex = "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa";
        String expectedTweakedPrivKeyHex = "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9";

        ECKey internalPrivKey = ECKey.fromPrivate(HexFormat.of().parseHex(internalPrivKeyHex));
        ECKey tweakedOutputKey = internalPrivKey.getTweakedOutputKey();
        Assertions.assertEquals(expectedTweakedPrivKeyHex, tweakedOutputKey.getPrivKey().toString(16));
    }

    @Test
    void testTweakPubKeyTestvectorBip341() {
        // test vector (without script path) from BIP341:
        // https://github.com/bitcoin/bips/blob/9a30c28574e62e26da77f14e33eb698b81268887/bip-0341/wallet-test-vectors.json#L6C36-L6C100
        String internalPubKeyHex = "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d";
        String expectedTweakedPubKey = "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343";
        String expectedAddress = "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5";

        ECKey internalPubKey = ECKey.fromPublicOnly(HexFormat.of().parseHex(internalPubKeyHex));
        ECKey tweakedOutputKey = internalPubKey.getTweakedOutputKey();
        Assertions.assertEquals(expectedTweakedPubKey, Utils.bytesToHex(tweakedOutputKey.getPubKeyXCoord()));
        // the y-coordinate of the resulting tweaked pubkey in this sample is odd, so the full pubkey will have 0x03 prefix
        Assertions.assertEquals("03" + expectedTweakedPubKey, Utils.bytesToHex(tweakedOutputKey.getPubKey()));
        // assert that the generated address matches the test vector
        Address address = ScriptType.P2TR.getAddress(internalPubKey);
        Assertions.assertEquals(expectedAddress, address.toString());
    }
}
