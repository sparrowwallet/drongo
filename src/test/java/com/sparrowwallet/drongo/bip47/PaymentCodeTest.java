package com.sparrowwallet.drongo.bip47;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.DumpedPrivateKey;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.wallet.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class PaymentCodeTest {
    @Test
    public void testNotificationAddress() throws InvalidPaymentCodeException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, MnemonicException {
        PaymentCode alicePaymentCode = new PaymentCode("PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA");
        Address aliceNotificationAddress = alicePaymentCode.getNotificationAddress();
        Assertions.assertEquals("1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW", aliceNotificationAddress.toString());

        ECKey alicePrivKey = DumpedPrivateKey.fromBase58("Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD").getKey();

        byte[] alicePayload = alicePaymentCode.getPayload();
        Assertions.assertEquals("010002b85034fb08a8bfefd22848238257b252721454bbbfba2c3667f168837ea2cdad671af9f65904632e2dcc0c6ad314e11d53fc82fa4c4ea27a4a14eccecc478fee00000000000000000000000000", Utils.bytesToHex(alicePayload));

        PaymentCode paymentCodeBob = new PaymentCode("PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97");
        ECKey bobNotificationPubKey = paymentCodeBob.getNotificationKey();
        Assertions.assertEquals("024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8", Utils.bytesToHex(bobNotificationPubKey.getPubKey()));

        TransactionOutPoint transactionOutPoint = new TransactionOutPoint(Sha256Hash.wrapReversed(Utils.hexToBytes("86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c")), 1);
        Assertions.assertEquals("86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000", Utils.bytesToHex(transactionOutPoint.bitcoinSerialize()));

        SecretPoint secretPoint = new SecretPoint(alicePrivKey.getPrivKeyBytes(), bobNotificationPubKey.getPubKey());
        Assertions.assertEquals("736a25d9250238ad64ed5da03450c6a3f4f8f4dcdf0b58d1ed69029d76ead48d", Utils.bytesToHex(secretPoint.ECDHSecretAsBytes()));

        byte[] blindingMask = PaymentCode.getMask(secretPoint.ECDHSecretAsBytes(), transactionOutPoint.bitcoinSerialize());
        Assertions.assertEquals("be6e7a4256cac6f4d4ed4639b8c39c4cb8bece40010908e70d17ea9d77b4dc57f1da36f2d6641ccb37cf2b9f3146686462e0fa3161ae74f88c0afd4e307adbd5", Utils.bytesToHex(blindingMask));

        byte[] blindedPaymentCode = PaymentCode.blind(alicePayload, blindingMask);
        Assertions.assertEquals("010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000", Utils.bytesToHex(blindedPaymentCode));

        Transaction transaction = new Transaction();
        List<ScriptChunk> inputChunks = List.of(ScriptChunk.fromData(Utils.hexToBytes("3045022100ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcfc0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801")), ScriptChunk.fromData(alicePrivKey.getPubKey()));
        transaction.addInput(transactionOutPoint.getHash(), transactionOutPoint.getIndex(), new Script(inputChunks));
        transaction.addOutput(10000, paymentCodeBob.getNotificationAddress());
        List<ScriptChunk> opReturnChunks = List.of(ScriptChunk.fromOpcode(ScriptOpCodes.OP_RETURN), ScriptChunk.fromData(blindedPaymentCode));
        transaction.addOutput(10000, new Script(opReturnChunks));
        Assertions.assertEquals("010000000186f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c010000006b483045022100ac8c6dbc482c79e86c18928a8b364923c774bfdb" +
                "d852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcfc0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3f2" +
                "c9ad8ffffffff0210270000000000001976a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac1027000000000000536a4c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb3" +
                "24d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b0000000000000000000000000000000000", Utils.bytesToHex(transaction.bitcoinSerialize()));
        Assertions.assertEquals("9414f1681fb1255bd168a806254321a837008dd4480c02226063183deb100204", transaction.getTxId().toString());

        ECKey alicePubKey = ECKey.fromPublicOnly(transaction.getInputs().get(0).getScriptSig().getChunks().get(1).data);
        Assertions.assertArrayEquals(alicePubKey.getPubKey(), alicePrivKey.getPubKey());

        DeterministicSeed bobSeed = new DeterministicSeed("reward upper indicate eight swift arch injury crystal super wrestle already dentist", "", 0, DeterministicSeed.Type.BIP39);
        Keystore bobKeystore = Keystore.fromSeed(bobSeed, List.of(new ChildNumber(47, true), ChildNumber.ZERO_HARDENED, ChildNumber.ZERO_HARDENED));
        ECKey bobNotificationPrivKey = bobKeystore.getBip47ExtendedPrivateKey().getKey(List.of(ChildNumber.ZERO_HARDENED, new ChildNumber(0)));

        SecretPoint bobSecretPoint = new SecretPoint(bobNotificationPrivKey.getPrivKeyBytes(), alicePubKey.getPubKey());
        Assertions.assertEquals("736a25d9250238ad64ed5da03450c6a3f4f8f4dcdf0b58d1ed69029d76ead48d", Utils.bytesToHex(bobSecretPoint.ECDHSecretAsBytes()));

        byte[] bobBlindingMask = PaymentCode.getMask(secretPoint.ECDHSecretAsBytes(), transaction.getInputs().get(0).getOutpoint().bitcoinSerialize());
        Assertions.assertEquals("be6e7a4256cac6f4d4ed4639b8c39c4cb8bece40010908e70d17ea9d77b4dc57f1da36f2d6641ccb37cf2b9f3146686462e0fa3161ae74f88c0afd4e307adbd5", Utils.bytesToHex(bobBlindingMask));

        PaymentCode unblindedPaymentCode = new PaymentCode(PaymentCode.blind(transaction.getOutputs().get(1).getScript().getChunks().get(1).data, blindingMask));
        Assertions.assertEquals(alicePaymentCode, unblindedPaymentCode);

        PaymentCode unblindedPaymentCode2 = PaymentCode.getPaymentCode(transaction, bobKeystore);
        Assertions.assertEquals(alicePaymentCode, unblindedPaymentCode2);
    }

    @Test
    public void testFromSeed() throws MnemonicException {
        DeterministicSeed aliceSeed = new DeterministicSeed("response seminar brave tip suit recall often sound stick owner lottery motion", "", 0, DeterministicSeed.Type.BIP39);
        Keystore aliceKeystore = Keystore.fromSeed(aliceSeed, List.of(new ChildNumber(47, true), ChildNumber.ZERO_HARDENED, ChildNumber.ZERO_HARDENED));

        DeterministicKey bip47PubKey = aliceKeystore.getExtendedPublicKey().getKey();
        PaymentCode alicePaymentCode = new PaymentCode(bip47PubKey.getPubKey(), bip47PubKey.getChainCode());
        Assertions.assertEquals("PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA", alicePaymentCode.toString());
    }

    @Test
    public void testPaymentAddress() throws MnemonicException, InvalidPaymentCodeException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException, NotSecp256k1Exception {
        DeterministicSeed seed = new DeterministicSeed("response seminar brave tip suit recall often sound stick owner lottery motion", "", 0, DeterministicSeed.Type.BIP39);
        Keystore keystore = Keystore.fromSeed(seed, List.of(new ChildNumber(47, true), ChildNumber.ZERO_HARDENED, ChildNumber.ZERO_HARDENED));
        DeterministicKey privateKey = keystore.getExtendedPrivateKey().getKey(List.of(ChildNumber.ZERO_HARDENED, ChildNumber.ZERO));

        PaymentCode paymentCodeBob = new PaymentCode("PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97");

        PaymentAddress paymentAddress0 = new PaymentAddress(paymentCodeBob, 0, privateKey.getPrivKeyBytes());
        ECKey sendKey0 = paymentAddress0.getSendECKey();
        Assertions.assertEquals("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", ScriptType.P2PKH.getAddress(sendKey0).toString());

        PaymentAddress paymentAddress1 = new PaymentAddress(paymentCodeBob, 1, privateKey.getPrivKeyBytes());
        ECKey sendKey1 = paymentAddress1.getSendECKey();
        Assertions.assertEquals("12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6", ScriptType.P2PKH.getAddress(sendKey1).toString());
    }

    @Test
    public void testChildWallet() throws MnemonicException, InvalidPaymentCodeException {
        DeterministicSeed aliceSeed = new DeterministicSeed("response seminar brave tip suit recall often sound stick owner lottery motion", "", 0, DeterministicSeed.Type.BIP39);
        Wallet aliceWallet = new Wallet();
        aliceWallet.setPolicyType(PolicyType.SINGLE);
        aliceWallet.setScriptType(ScriptType.P2PKH);
        aliceWallet.getKeystores().add(Keystore.fromSeed(aliceSeed, aliceWallet.getScriptType().getDefaultDerivation()));
        aliceWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2PKH, aliceWallet.getKeystores(), 1));

        PaymentCode paymentCodeBob = new PaymentCode("PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97");

        Wallet aliceBip47Wallet = aliceWallet.addChildWallet(paymentCodeBob, ScriptType.P2PKH, "Alice");
        PaymentCode paymentCodeAlice = aliceBip47Wallet.getKeystores().get(0).getPaymentCode();

        Assertions.assertEquals(aliceWallet.getPaymentCode(), aliceBip47Wallet.getPaymentCode());
        Assertions.assertEquals("PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA", paymentCodeAlice.toString());
        Assertions.assertEquals("1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW", paymentCodeAlice.getNotificationAddress().toString());

        WalletNode sendNode0 = aliceBip47Wallet.getFreshNode(KeyPurpose.SEND);
        Address address0 = sendNode0.getAddress();
        Assertions.assertEquals("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", address0.toString());

        WalletNode sendNode1 = aliceBip47Wallet.getFreshNode(KeyPurpose.SEND, sendNode0);
        Address address1 = sendNode1.getAddress();
        Assertions.assertEquals("12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6", address1.toString());

        WalletNode sendNode2 = aliceBip47Wallet.getFreshNode(KeyPurpose.SEND, sendNode1);
        Address address2 = sendNode2.getAddress();
        Assertions.assertEquals("1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc", address2.toString());

        DeterministicSeed bobSeed = new DeterministicSeed("reward upper indicate eight swift arch injury crystal super wrestle already dentist", "", 0, DeterministicSeed.Type.BIP39);
        Wallet bobWallet = new Wallet();
        bobWallet.setPolicyType(PolicyType.SINGLE);
        bobWallet.setScriptType(ScriptType.P2PKH);
        bobWallet.getKeystores().add(Keystore.fromSeed(bobSeed, bobWallet.getScriptType().getDefaultDerivation()));
        bobWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2PKH, bobWallet.getKeystores(), 1));

        Wallet bobBip47Wallet = bobWallet.addChildWallet(paymentCodeAlice, ScriptType.P2PKH, "Bob");
        Assertions.assertEquals(paymentCodeBob.toString(), bobBip47Wallet.getKeystores().get(0).getPaymentCode().toString());
        Assertions.assertEquals("1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV", paymentCodeBob.getNotificationAddress().toString());

        WalletNode receiveNode0 = bobBip47Wallet.getFreshNode(KeyPurpose.RECEIVE);
        Address receiveAddress0 = receiveNode0.getAddress();
        Assertions.assertEquals("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", receiveAddress0.toString());

        WalletNode receiveNode1 = bobBip47Wallet.getFreshNode(KeyPurpose.RECEIVE, receiveNode0);
        Address receiveAddress1 = receiveNode1.getAddress();
        Assertions.assertEquals("12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6", receiveAddress1.toString());

        WalletNode receiveNode2 = bobBip47Wallet.getFreshNode(KeyPurpose.RECEIVE, receiveNode1);
        Address receiveAddress2 = receiveNode2.getAddress();
        Assertions.assertEquals("1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc", receiveAddress2.toString());

        ECKey privKey0 = bobWallet.getKeystores().get(0).getKey(receiveNode0);
        ECKey pubKey0 = bobWallet.getKeystores().get(0).getPubKey(receiveNode0);
        Assertions.assertArrayEquals(privKey0.getPubKey(), pubKey0.getPubKey());

        ECKey privKey1 = bobWallet.getKeystores().get(0).getKey(receiveNode1);
        ECKey pubKey1 = bobWallet.getKeystores().get(0).getPubKey(receiveNode1);
        Assertions.assertArrayEquals(privKey1.getPubKey(), pubKey1.getPubKey());
    }
}
