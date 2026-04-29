package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.address.P2TRAddress;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.wallet.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public class SilentPaymentUtilsTest {
    private static final String STANDARD_SCAN_PRIV = "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
    private static final String STANDARD_SPEND_PRIV = "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3";

    // BIP352 tweak compute tests.

    @Test
    public void testTweak() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(Utils.hexToBytes("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")));
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(Utils.hexToBytes("48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792")));
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(PolicyType.SINGLE_HD, ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

        Map<HashIndex, Script> spentScriptPubKeys = new HashMap<>();
        HashIndex hashIndex0 = new HashIndex(transaction.getInputs().getFirst().getOutpoint().getHash(), transaction.getInputs().getFirst().getOutpoint().getIndex());
        Script spentScriptPubKey0 = new Script(Utils.hexToBytes("76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac"));
        HashIndex hashIndex1 = new HashIndex(transaction.getInputs().getLast().getOutpoint().getHash(), transaction.getInputs().getLast().getOutpoint().getIndex());
        Script spentScriptPubKey1 = new Script(Utils.hexToBytes("76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac"));
        spentScriptPubKeys.put(hashIndex0, spentScriptPubKey0);
        spentScriptPubKeys.put(hashIndex1, spentScriptPubKey1);

        byte[] tweak = SilentPaymentUtils.getTweak(transaction, spentScriptPubKeys);
        Assertions.assertNotNull(tweak);
        Assertions.assertEquals("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004", Utils.bytesToHex(tweak));
    }

    @Test
    public void testTweakReversed() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(Utils.hexToBytes("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")));
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(Utils.hexToBytes("48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792")));
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(PolicyType.SINGLE_HD, ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

        Map<HashIndex, Script> spentScriptPubKeys = new HashMap<>();
        HashIndex hashIndex0 = new HashIndex(transaction.getInputs().getFirst().getOutpoint().getHash(), transaction.getInputs().getFirst().getOutpoint().getIndex());
        Script spentScriptPubKey0 = new Script(Utils.hexToBytes("76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac"));
        HashIndex hashIndex1 = new HashIndex(transaction.getInputs().getLast().getOutpoint().getHash(), transaction.getInputs().getLast().getOutpoint().getIndex());
        Script spentScriptPubKey1 = new Script(Utils.hexToBytes("76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac"));
        spentScriptPubKeys.put(hashIndex0, spentScriptPubKey0);
        spentScriptPubKeys.put(hashIndex1, spentScriptPubKey1);

        byte[] tweak = SilentPaymentUtils.getTweak(transaction, spentScriptPubKeys);
        Assertions.assertNotNull(tweak);
        Assertions.assertEquals("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004", Utils.bytesToHex(tweak));
    }

    @Test
    public void testTweakChange() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(Utils.hexToBytes("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")));
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(Utils.hexToBytes("473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338")));
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(PolicyType.SINGLE_HD, ECKey.fromPublicOnly(Utils.hexToBytes("be368e28979d950245d742891ae6064020ba548c1e2e65a639a8bb0675d95cff"))));

        Map<HashIndex, Script> spentScriptPubKeys = new HashMap<>();
        HashIndex hashIndex0 = new HashIndex(transaction.getInputs().getFirst().getOutpoint().getHash(), transaction.getInputs().getFirst().getOutpoint().getIndex());
        Script spentScriptPubKey0 = new Script(Utils.hexToBytes("76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac"));
        HashIndex hashIndex1 = new HashIndex(transaction.getInputs().getLast().getOutpoint().getHash(), transaction.getInputs().getLast().getOutpoint().getIndex());
        Script spentScriptPubKey1 = new Script(Utils.hexToBytes("76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac"));
        spentScriptPubKeys.put(hashIndex0, spentScriptPubKey0);
        spentScriptPubKeys.put(hashIndex1, spentScriptPubKey1);

        byte[] tweak = SilentPaymentUtils.getTweak(transaction, spentScriptPubKeys);
        Assertions.assertNotNull(tweak);
        Assertions.assertEquals("0314bec14463d6c0181083d607fecfba67bb83f95915f6f247975ec566d5642ee8", Utils.bytesToHex(tweak));
    }

    @Test
    public void testTweakTaprootEvenY() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(new byte[0]), new TransactionWitness(transaction, List.of(Utils.hexToBytes("0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b"))));
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(new byte[0]), new TransactionWitness(transaction, List.of(Utils.hexToBytes("0140bd1e708f92dbeaf24a6b8dd22e59c6274355424d62baea976b449e220fd75b13578e262ab11b7aa58e037f0c6b0519b66803b7d9decaa1906dedebfb531c56c1"))));
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(PolicyType.SINGLE_HD, ECKey.fromPublicOnly(Utils.hexToBytes("de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb"))));

        Map<HashIndex, Script> spentScriptPubKeys = new HashMap<>();
        HashIndex hashIndex0 = new HashIndex(transaction.getInputs().getFirst().getOutpoint().getHash(), transaction.getInputs().getFirst().getOutpoint().getIndex());
        Script spentScriptPubKey0 = new Script(Utils.hexToBytes("51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5"));
        HashIndex hashIndex1 = new HashIndex(transaction.getInputs().getLast().getOutpoint().getHash(), transaction.getInputs().getLast().getOutpoint().getIndex());
        Script spentScriptPubKey1 = new Script(Utils.hexToBytes("5120782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338"));
        spentScriptPubKeys.put(hashIndex0, spentScriptPubKey0);
        spentScriptPubKeys.put(hashIndex1, spentScriptPubKey1);

        byte[] tweak = SilentPaymentUtils.getTweak(transaction, spentScriptPubKeys);
        Assertions.assertNotNull(tweak);
        Assertions.assertEquals("02dc59cc8e8873b65c1dd5c416d4fbeb647372c329bd84a70c05b310e222e2c183", Utils.bytesToHex(tweak));
    }

    @Test
    public void testTweakTaprootMixedY() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(new byte[0]), new TransactionWitness(transaction, List.of(Utils.hexToBytes("0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b"))));
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(new byte[0]), new TransactionWitness(transaction, List.of(Utils.hexToBytes("01400a4d0dca6293f40499394d7eefe14a1de11e0e3454f51de2e802592abf5ee549042a1b1a8fb2e149ee9dd3f086c1b69b2f182565ab6ecf599b1ec9ebadfda6c5"))));
        transaction.addOutput(1000L, new P2TRAddress(Utils.hexToBytes("77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf26b99f1")).getOutputScript());

        Map<HashIndex, Script> spentScriptPubKeys = new HashMap<>();
        HashIndex hashIndex0 = new HashIndex(transaction.getInputs().getFirst().getOutpoint().getHash(), transaction.getInputs().getFirst().getOutpoint().getIndex());
        Script spentScriptPubKey0 = new Script(Utils.hexToBytes("51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5"));
        HashIndex hashIndex1 = new HashIndex(transaction.getInputs().getLast().getOutpoint().getHash(), transaction.getInputs().getLast().getOutpoint().getIndex());
        Script spentScriptPubKey1 = new Script(Utils.hexToBytes("51208c8d23d4764feffcd5e72e380802540fa0f88e3d62ad5e0b47955f74d7b283c4"));
        spentScriptPubKeys.put(hashIndex0, spentScriptPubKey0);
        spentScriptPubKeys.put(hashIndex1, spentScriptPubKey1);

        byte[] tweak = SilentPaymentUtils.getTweak(transaction, spentScriptPubKeys);
        Assertions.assertNotNull(tweak);
        Assertions.assertEquals("03b990f5b1d90ea8fd4bdd5c856a9dfe17035d196958062e2c6cb4c99e413f3548", Utils.bytesToHex(tweak));

        ECKey tweakKey = ECKey.fromPublicOnly(tweak);
        BigInteger scanPrivateKey = new BigInteger(1, Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey sharedSecret = tweakKey.multiply(scanPrivateKey, true);
        Assertions.assertEquals("030e7f5ca4bf109fc35c8c2d878f756c891ac04c456cc5f0b05fcec4d3b2b1beb2", Utils.bytesToHex(sharedSecret.getPubKey()));
        byte[] tk = Utils.taggedHash(SilentPaymentUtils.BIP_0352_SHARED_SECRET_TAG, Utils.concat(sharedSecret.getPubKey(true), new byte[4]));
        ECKey tkKey = ECKey.fromPrivate(tk);
        ECKey bSpend = ECKey.fromPublicOnly(ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SPEND_PRIV)));
        ECKey Pk = bSpend.add(tkKey, true);
        Assertions.assertEquals("77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf26b99f1", Utils.bytesToHex(Pk.getPubKeyXCoord()));
        Address address = new P2TRAddress(Pk.getPubKeyXCoord());
        Assertions.assertEquals(transaction.getOutputs().getFirst().getScript().getToAddress(), address);
    }

    @Test
    public void testInvalidOutput() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(Utils.hexToBytes("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")));
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(Utils.hexToBytes("48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792")));
        transaction.addOutput(1000L, ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

        Assertions.assertFalse(SilentPaymentUtils.containsTaprootOutput(transaction));
    }

    // BIP352 send-side compute address tests.

    @Test
    public void testSimpleSendTwoInputs() throws InvalidSilentPaymentException {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(Utils.hexToBytes("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")));
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(Utils.hexToBytes("48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792")));
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(PolicyType.SINGLE_HD, ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

        Map<HashIndex, Script> spentScriptPubKeys = new HashMap<>();
        HashIndex hashIndex0 = new HashIndex(transaction.getInputs().getFirst().getOutpoint().getHash(), transaction.getInputs().getFirst().getOutpoint().getIndex());
        Script spentScriptPubKey0 = new Script(Utils.hexToBytes("76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac"));
        HashIndex hashIndex1 = new HashIndex(transaction.getInputs().getLast().getOutpoint().getHash(), transaction.getInputs().getLast().getOutpoint().getIndex());
        Script spentScriptPubKey1 = new Script(Utils.hexToBytes("76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac"));
        spentScriptPubKeys.put(hashIndex0, spentScriptPubKey0);
        spentScriptPubKeys.put(hashIndex1, spentScriptPubKey1);

        byte[] tweak = SilentPaymentUtils.getTweak(transaction, spentScriptPubKeys);
        Assertions.assertNotNull(tweak);
        Assertions.assertEquals("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004", Utils.bytesToHex(tweak));

        ECKey tweakKey = ECKey.fromPublicOnly(tweak);
        BigInteger scanPrivateKey = new BigInteger(1, Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey sharedSecret = tweakKey.multiply(scanPrivateKey, true);
        byte[] tk = Utils.taggedHash(SilentPaymentUtils.BIP_0352_SHARED_SECRET_TAG, Utils.concat(sharedSecret.getPubKey(true), new byte[4]));
        ECKey tkKey = ECKey.fromPrivate(tk);
        ECKey bSpend = ECKey.fromPublicOnly(ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SPEND_PRIV)));
        ECKey Pk = bSpend.add(tkKey, true);
        Address address = new P2TRAddress(Pk.getPubKeyXCoord());
        Assertions.assertEquals("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1", Utils.bytesToHex(address.getData()));

        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE_HD);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals(silentPayments.getFirst().getAddress(), address);
        Assertions.assertEquals("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSimpleSendTwoInputsReversed() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE_HD);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSimpleSendTwoInputsSameTransaction() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE_HD);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 3);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 7);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("79e71baa2ba3fc66396de3a04f168c7bf24d6870ec88ca877754790c1db357b6", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSimpleSendTwoInputsSameTransactionReversed() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE_HD);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 7);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 3);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("f4c2da807f89cb1501f1a77322a895acfb93c28e08ed2724d2beb8e44539ba38", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testOutpointOrderingIndex() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE_HD);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 1);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 256);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("a85ef8701394b517a4b35217c4bd37ac01ebeed4b008f8d0879f9e09ba95319c", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientSamePubKey() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE_HD);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("548ae55c8eec1e736e8d3e520f011f1f42a56d166116ad210b3937599f87f566", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootOnlyEvenY() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE_HD);
        sendWallet.setScriptType(ScriptType.P2TR);
        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0);
        ECKey privKey0 = new ECKey() {
            @Override
            public ECKey getTweakedOutputKey() {
                return ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
            }
        };
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0);
        ECKey privKey1 = new ECKey() {
            @Override
            public ECKey getTweakedOutputKey() {
                return ECKey.fromPrivate(Utils.hexToBytes("fc8716a97a48ba9a05a98ae47b5cd201a25a7fd5d8b73c203c5f7b6b6b3b6ad7"));
            }
        };
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootOnlyMixedY() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE_HD);
        sendWallet.setScriptType(ScriptType.P2TR);
        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0);
        ECKey privKey0 = new ECKey() {
            @Override
            public ECKey getTweakedOutputKey() {
                return ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
            }
        };
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0);
        ECKey privKey1 = new ECKey() {
            @Override
            public ECKey getTweakedOutputKey() {
                return ECKey.fromPrivate(Utils.hexToBytes("1d37787c2b7116ee983e9f9c13269df29091b391c04db94239e0d2bc2182c3bf"));
            }
        };
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf26b99f1", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootEvenYAndNonTaproot() throws InvalidSilentPaymentException {
        Wallet taprootWallet = new Wallet();
        taprootWallet.setPolicyType(PolicyType.SINGLE_HD);
        taprootWallet.setScriptType(ScriptType.P2TR);
        Map<WalletNode, ECKey> taprootPrivateKeys = new LinkedHashMap<>();

        Wallet segwitWallet = new Wallet();
        segwitWallet.setPolicyType(PolicyType.SINGLE_HD);
        segwitWallet.setScriptType(ScriptType.P2WPKH);
        Map<WalletNode, ECKey> segwitPrivateKeys = new LinkedHashMap<>();

        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(taprootWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0);
        ECKey privKey0 = new ECKey() {
            @Override
            public ECKey getTweakedOutputKey() {
                return ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
            }
        };
        utxos.put(ref0, walletNode0);
        taprootPrivateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(segwitWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("8d4751f6e8a3586880fb66c19ae277969bd5aa06f61c4ee2f1e2486efdf666d3"));
        utxos.put(ref1, walletNode1);
        segwitPrivateKeys.put(walletNode1, privKey1);

        TestKeystore taprootKeystore = new TestKeystore(taprootPrivateKeys);
        taprootWallet.getKeystores().add(taprootKeystore);
        taprootWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, taprootWallet.getKeystores(), 1));

        TestKeystore segwitKeystore = new TestKeystore(segwitPrivateKeys);
        segwitWallet.getKeystores().add(segwitKeystore);
        segwitWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, segwitWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("30523cca96b2a9ae3c98beb5e60f7d190ec5bc79b2d11a0b2d4d09a608c448f0", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootOddYAndNonTaproot() throws InvalidSilentPaymentException {
        Wallet taprootWallet = new Wallet();
        taprootWallet.setPolicyType(PolicyType.SINGLE_HD);
        taprootWallet.setScriptType(ScriptType.P2TR);
        Map<WalletNode, ECKey> taprootPrivateKeys = new LinkedHashMap<>();

        Wallet segwitWallet = new Wallet();
        segwitWallet.setPolicyType(PolicyType.SINGLE_HD);
        segwitWallet.setScriptType(ScriptType.P2WPKH);
        Map<WalletNode, ECKey> segwitPrivateKeys = new LinkedHashMap<>();

        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(taprootWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0);
        ECKey privKey0 = new ECKey() {
            @Override
            public ECKey getTweakedOutputKey() {
                return ECKey.fromPrivate(Utils.hexToBytes("1d37787c2b7116ee983e9f9c13269df29091b391c04db94239e0d2bc2182c3bf"));
            }
        };
        utxos.put(ref0, walletNode0);
        taprootPrivateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(segwitWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("8d4751f6e8a3586880fb66c19ae277969bd5aa06f61c4ee2f1e2486efdf666d3"));
        utxos.put(ref1, walletNode1);
        segwitPrivateKeys.put(walletNode1, privKey1);

        TestKeystore taprootKeystore = new TestKeystore(taprootPrivateKeys);
        taprootWallet.getKeystores().add(taprootKeystore);
        taprootWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, taprootWallet.getKeystores(), 1));

        TestKeystore segwitKeystore = new TestKeystore(segwitPrivateKeys);
        segwitWallet.getKeystores().add(segwitKeystore);
        segwitWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, segwitWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("359358f59ee9e9eec3f00bdf4882570fd5c182e451aa2650b788544aff012a3a", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testMultipleOutputsSameRecipient() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE_HD);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress0 = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        SilentPaymentAddress silentPaymentAddress1 = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress0, "First", 0, false), new SilentPayment(silentPaymentAddress1, "Second", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(2, silentPayments.size());
        Assertions.assertEquals("First", silentPayments.getFirst().getLabel());
        Assertions.assertEquals("f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
        Assertions.assertEquals("Second", silentPayments.getLast().getLabel());
        Assertions.assertEquals("e976a58fbd38aeb4e6093d4df02e9c1de0c4513ae0c588cef68cda5b2f8834ca", Utils.bytesToHex(silentPayments.getLast().getAddress().getData()));
    }

    @Test
    public void testMultipleOutputsMultipleRecipients() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE_HD);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress0 = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        SilentPaymentAddress silentPaymentAddress1 = SilentPaymentAddress.from("sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn");
        SilentPaymentAddress silentPaymentAddress2 = SilentPaymentAddress.from("sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress0, "First", 0, false), new SilentPayment(silentPaymentAddress1, "Second", 0, false), new SilentPayment(silentPaymentAddress2, "Third", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(3, silentPayments.size());
        Assertions.assertEquals("First", silentPayments.getFirst().getLabel());
        Assertions.assertEquals("f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
        Assertions.assertEquals("Second", silentPayments.get(1).getLabel());
        Assertions.assertEquals("841792c33c9dc6193e76744134125d40add8f2f4a96475f28ba150be032d64e8", Utils.bytesToHex(silentPayments.get(1).getAddress().getData()));
        Assertions.assertEquals("Third", silentPayments.getLast().getLabel());
        Assertions.assertEquals("2e847bb01d1b491da512ddd760b8509617ee38057003d6115d00ba562451323a", Utils.bytesToHex(silentPayments.getLast().getAddress().getData()));
    }

    // BIP352 key sum tests.

    @Test
    public void testIntermediateZeroSum() throws InvalidSilentPaymentException {
        // BIP 352 test vector: Input keys intermediate sum is zero but final sum is non-zero
        // Keys: [A, -A mod n, A] where:
        // A        = a6df6a0bb448992a301df4258e06a89fe7cf7146f59ac3bd5ff26083acb22ceb
        // -A mod n = 592095f44bb766d5cfe20bda71f9575ed2df6b9fb9addc7e5fdffe0923841456
        // Expected sum = A (non-zero)

        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE_HD);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<HashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        // Input 0: key A
        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        HashIndex ref0 = new HashIndex(Sha256Hash.wrap("3a286147b25e16ae80aff406f2673c6e565418c40f45c071245cdebc8a94174e"), 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("a6df6a0bb448992a301df4258e06a89fe7cf7146f59ac3bd5ff26083acb22ceb"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        // Input 1: key -A mod n
        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        HashIndex ref1 = new HashIndex(Sha256Hash.wrap("3a286147b25e16ae80aff406f2673c6e565418c40f45c071245cdebc8a94174e"), 1);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("592095f44bb766d5cfe20bda71f9575ed2df6b9fb9addc7e5fdffe0923841456"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        // Input 2: key A (same as input 0)
        WalletNode walletNode2 = new WalletNode(sendWallet, "/0/2");
        HashIndex ref2 = new HashIndex(Sha256Hash.wrap("3a286147b25e16ae80aff406f2673c6e565418c40f45c071245cdebc8a94174e"), 2);
        ECKey privKey2 = ECKey.fromPrivate(Utils.hexToBytes("a6df6a0bb448992a301df4258e06a89fe7cf7146f59ac3bd5ff26083acb22ceb"));
        utxos.put(ref2, walletNode2);
        privateKeys.put(walletNode2, privKey2);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        ECKey summedKey = SilentPaymentUtils.getSummedPrivateKey(utxos.values());
        Assertions.assertEquals("a6df6a0bb448992a301df4258e06a89fe7cf7146f59ac3bd5ff26083acb22ceb", Utils.bytesToHex(summedKey.getPrivKeyBytes()));
    }

    private static class TestKeystore extends Keystore {
        private final Map<WalletNode, ECKey> privateKeys;

        private TestKeystore(Map<WalletNode, ECKey> privateKeys) {
            this.privateKeys = privateKeys;
        }

        @Override
        public ECKey getKey(WalletNode walletNode) {
            return privateKeys.get(walletNode);
        }

        @Override
        public boolean hasPrivateKey() {
            return true;
        }
    }

    // BIP352 receive-side scan tests.

    private static ECKey standardSpendPub() {
        ECKey priv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SPEND_PRIV));
        return ECKey.fromPublicOnly(priv.getPubKey(true));
    }

    private static Transaction txWithP2trOutputs(String... xOnlyHexes) {
        Transaction tx = new Transaction();
        for(String hex : xOnlyHexes) {
            // Use the byte[] overload to commit the raw x-only pubkey as-is, with no BIP341 taproot
            // tweaking. SP output keys are already the final on-chain key.
            tx.addOutput(0L, ScriptType.P2TR.getOutputScript(Utils.hexToBytes(hex)));
        }
        return tx;
    }

    @Test
    public void testScanSimplestCase() throws InvalidSilentPaymentException {
        // BIP352 case 0: "Simple send: two inputs"
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004");
        Transaction tx = txWithP2trOutputs("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1");

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), tweakKey, tx.getOutputs());

        Assertions.assertEquals(1, matches.size());
        SilentPaymentScanMatch m = matches.getFirst();
        Assertions.assertEquals(0, m.outputIndex());
        Assertions.assertNull(m.labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("f438b40179a3c4262de12986c0e6cce0634007cdc79c1dcd3e20b9ebc2e7eef6"), m.tweak());
    }

    @Test
    public void testScanTaprootEvenY() throws InvalidSilentPaymentException {
        // BIP352 case 6: "Single recipient: taproot only inputs with even y-values"
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("02dc59cc8e8873b65c1dd5c416d4fbeb647372c329bd84a70c05b310e222e2c183");
        Transaction tx = txWithP2trOutputs("de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb");

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), tweakKey, tx.getOutputs());

        Assertions.assertEquals(1, matches.size());
        Assertions.assertEquals(0, matches.getFirst().outputIndex());
        Assertions.assertNull(matches.getFirst().labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("3fb9ce5ce1746ced103c8ed254e81f6690764637ddbc876ec1f9b3ddab776b03"), matches.getFirst().tweak());
    }

    @Test
    public void testScanTaprootOddY() throws InvalidSilentPaymentException {
        // BIP352 case 7: "Single recipient: taproot only with mixed even/odd y-values"
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("03b990f5b1d90ea8fd4bdd5c856a9dfe17035d196958062e2c6cb4c99e413f3548");
        Transaction tx = txWithP2trOutputs("77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf26b99f1");

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), tweakKey, tx.getOutputs());

        Assertions.assertEquals(1, matches.size());
        Assertions.assertEquals(0, matches.getFirst().outputIndex());
        Assertions.assertNull(matches.getFirst().labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("f5382508609771068ed079b24e1f72e4a17ee6d1c979066bf1d4e2a5676f09d4"), matches.getFirst().tweak());
    }

    @Test
    public void testScanMultipleOutputsSameRecipient() throws InvalidSilentPaymentException {
        // BIP352 case 10: "Multiple outputs: multiple outputs, same recipient"
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("0314bec14463d6c0181083d607fecfba67bb83f95915f6f247975ec566d5642ee8");
        Transaction tx = txWithP2trOutputs(
                "e976a58fbd38aeb4e6093d4df02e9c1de0c4513ae0c588cef68cda5b2f8834ca",
                "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac");

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), tweakKey, tx.getOutputs());

        Assertions.assertEquals(2, matches.size());
        Assertions.assertEquals(0, matches.get(0).outputIndex());
        Assertions.assertNull(matches.get(0).labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("d97e442d110c0bdd31161a7bb6e7862e038d02a09b1484dfbb463f2e0f7c9230"), matches.get(0).tweak());
        Assertions.assertEquals(1, matches.get(1).outputIndex());
        Assertions.assertNull(matches.get(1).labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("33ce085c3c11eaad13694aae3c20301a6c83382ec89a7cde96c6799e2f88805a"), matches.get(1).tweak());
    }

    @Test
    public void testScanLabelEvenParity() throws InvalidSilentPaymentException {
        // BIP352 case 12: "Receiving with labels: label with even parity" — label 2 match.
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("0314bec14463d6c0181083d607fecfba67bb83f95915f6f247975ec566d5642ee8");
        Transaction tx = txWithP2trOutputs("d014d4860f67d607d60b1af70e0ee236b99658b61bb769832acbbe87c374439a");

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Set.of(2, 3, 1001337), tweakKey, tx.getOutputs());

        Assertions.assertEquals(1, matches.size());
        Assertions.assertEquals(0, matches.getFirst().outputIndex());
        Assertions.assertEquals(2, matches.getFirst().labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("51d4e9d0d482b5700109b4b2e16ff508269b03d800192a043d61dca4a0a72a52"), matches.getFirst().tweak());
    }

    @Test
    public void testScanLabelOddParity() throws InvalidSilentPaymentException {
        // BIP352 case 13: "Receiving with labels: label with odd parity" — label 3 match.
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("0314bec14463d6c0181083d607fecfba67bb83f95915f6f247975ec566d5642ee8");
        Transaction tx = txWithP2trOutputs("67626aebb3c4307cf0f6c39ca23247598fabf675ab783292eb2f81ae75ad1f8c");

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Set.of(2, 3, 1001337), tweakKey, tx.getOutputs());

        Assertions.assertEquals(1, matches.size());
        Assertions.assertEquals(3, matches.getFirst().labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("6024ae214876356b8d917716e7707d267ae16a0fdb07de2a786b74a7bbcddead"), matches.getFirst().tweak());
    }

    @Test
    public void testScanLabelLargeInteger() throws InvalidSilentPaymentException {
        // BIP352 case 14: "Receiving with labels: large label integer" — label 1001337 match.
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("0314bec14463d6c0181083d607fecfba67bb83f95915f6f247975ec566d5642ee8");
        Transaction tx = txWithP2trOutputs("7efa60ce78ac343df8a013a2027c6c5ef29f9502edcbd769d2c21717fecc5951");

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Set.of(2, 3, 1001337), tweakKey, tx.getOutputs());

        Assertions.assertEquals(1, matches.size());
        Assertions.assertEquals(1001337, matches.getFirst().labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("e336b92330c33030285ce42e4115ad92d5197913c88e06b9072b4a9b47c664a2"), matches.getFirst().tweak());
    }

    @Test
    public void testScanUnlabeledAndLabeled() throws InvalidSilentPaymentException {
        // BIP352 case 15: "Multiple outputs with labels: un-labeled and labeled address; same recipient".
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("0314bec14463d6c0181083d607fecfba67bb83f95915f6f247975ec566d5642ee8");
        Transaction tx = txWithP2trOutputs("39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",  // labeled (m=1)
                "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac"); // unlabeled

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Set.of(1), tweakKey, tx.getOutputs());

        Assertions.assertEquals(2, matches.size());
        Assertions.assertEquals(0, matches.get(0).outputIndex());
        Assertions.assertEquals(1, matches.get(0).labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("43100f89f1a6bf10081c92b473ffc57ceac7dbed600b6aba9bb3976f17dbb914"), matches.get(0).tweak());
        Assertions.assertEquals(1, matches.get(1).outputIndex());
        Assertions.assertNull(matches.get(1).labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("33ce085c3c11eaad13694aae3c20301a6c83382ec89a7cde96c6799e2f88805a"), matches.get(1).tweak());
    }

    @Test
    public void testScanMultipleLabeledOutputs() throws InvalidSilentPaymentException {
        // BIP352 case 16: "Multiple outputs with labels: multiple outputs for labeled address; same recipient".
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("0314bec14463d6c0181083d607fecfba67bb83f95915f6f247975ec566d5642ee8");
        Transaction tx = txWithP2trOutputs("39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c", "83dc944e61603137294829aed56c74c9b087d80f2c021b98a7fae5799000696c");

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Set.of(1), tweakKey, tx.getOutputs());

        Assertions.assertEquals(2, matches.size());
        Assertions.assertEquals(1, matches.get(0).labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("43100f89f1a6bf10081c92b473ffc57ceac7dbed600b6aba9bb3976f17dbb914"), matches.get(0).tweak());
        Assertions.assertEquals(1, matches.get(1).labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("9d5fd3b91cac9ddfea6fc2e6f9386f680e6cee623cda02f53706306c081de87f"), matches.get(1).tweak());
    }

    @Test
    public void testScanChange() throws InvalidSilentPaymentException {
        // BIP352 case 18 receiver 0: "Single recipient: use silent payments for sender change" — label 0.
        // Note: label 0 (change) is implicit even when not in labelIndices; this test uses an empty set
        // to verify the implicit subscription.
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes("11b7a82e06ca2648d5fded2366478078ec4fc9dc1d8ff487518226f229d768fd"));
        ECKey spendPriv = ECKey.fromPrivate(Utils.hexToBytes("b8f87388cbb41934c50daca018901b00070a5ff6cc25a7e9e716a9d5b9e4d664"));
        ECKey spendPub = ECKey.fromPublicOnly(spendPriv.getPubKey(true));
        byte[] tweakKey = Utils.hexToBytes("0314bec14463d6c0181083d607fecfba67bb83f95915f6f247975ec566d5642ee8");
        Transaction tx = txWithP2trOutputs("be368e28979d950245d742891ae6064020ba548c1e2e65a639a8bb0675d95cff",  // change (m=0)
                "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac"); // unrelated (different recipient)

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), tweakKey, tx.getOutputs());

        Assertions.assertEquals(1, matches.size());
        Assertions.assertEquals(0, matches.getFirst().outputIndex());
        Assertions.assertEquals(0, matches.getFirst().labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("80cd767ed20bd0bb7d8ea5e803f8c381293a62e8a073cf46fb0081da46e64e1f"), matches.getFirst().tweak());
    }

    @Test
    public void testScanIgnoresUnrelatedOutputs() throws InvalidSilentPaymentException {
        // BIP352 case 23: "Recipient ignores unrelated outputs" — both outputs are P2TR but neither
        // pays this recipient. Verifies BIP352 termination at first non-matching k.
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("0314bec14463d6c0181083d607fecfba67bb83f95915f6f247975ec566d5642ee8");
        Transaction tx = txWithP2trOutputs("841792c33c9dc6193e76744134125d40add8f2f4a96475f28ba150be032d64e8", "782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338");

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), tweakKey, tx.getOutputs());

        Assertions.assertTrue(matches.isEmpty());
    }

    @Test
    public void testScanMatchedAndUnmatchedOutputs() throws InvalidSilentPaymentException {
        // Synthetic: real match from case 0 + an unrelated P2TR output. Verifies the matched output
        // is returned and the algorithm terminates after consuming it (rather than looping over the
        // unmatched output indefinitely).
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004");
        Transaction tx = txWithP2trOutputs("841792c33c9dc6193e76744134125d40add8f2f4a96475f28ba150be032d64e8",  // unrelated
                "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"); // case 0 match

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), tweakKey, tx.getOutputs());

        Assertions.assertEquals(1, matches.size());
        Assertions.assertEquals(1, matches.getFirst().outputIndex());
        Assertions.assertNull(matches.getFirst().labelIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("f438b40179a3c4262de12986c0e6cce0634007cdc79c1dcd3e20b9ebc2e7eef6"), matches.getFirst().tweak());
    }

    @Test
    public void testScanInvalidTweakKey() {
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        Transaction tx = txWithP2trOutputs("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1");

        // Wrong length
        Assertions.assertThrows(IllegalArgumentException.class, () -> SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), new byte[32], tx.getOutputs()));

        // Right length but not on curve
        byte[] notOnCurve = new byte[33];
        notOnCurve[0] = 0x02;
        Assertions.assertThrows(IllegalArgumentException.class, () -> SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), notOnCurve, tx.getOutputs()));
    }

    @Test
    public void testScanEmptyOutputs() throws InvalidSilentPaymentException {
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004");

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), tweakKey, Collections.emptyList());

        Assertions.assertTrue(matches.isEmpty());
    }

    @Test
    public void testScanNonP2trOutputs() throws InvalidSilentPaymentException {
        // A transaction with only a P2WPKH output should produce no matches and no error.
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004");

        Transaction tx = new Transaction();
        ECKey randomKey = ECKey.fromPublicOnly(Utils.hexToBytes("025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5"));
        tx.addOutput(0L, ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, randomKey));

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), tweakKey, tx.getOutputs());

        Assertions.assertTrue(matches.isEmpty());
    }

    @Test
    public void testScanKMaxCap() throws InvalidSilentPaymentException {
        // BIP352 case 27: a malicious sender constructs a transaction with K_MAX+1 outputs all
        // paying this recipient. The receiver must stop after K_MAX matches and ignore any further
        // candidates to bound DoS exposure. The vector doesn't enumerate the 2324 outputs, so we
        // synthesize the equivalent scenario by deriving K_MAX+1 unlabeled SP output keys against
        // case 0's recipient via the sender-side BIP352 math, then verify the scan returns exactly
        // K_MAX matches in order.
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004");

        ECKey tweakKeyPoint = ECKey.fromPublicOnly(tweakKey);
        ECKey sharedSecret = tweakKeyPoint.multiply(scanPriv.getPrivKey(), true);
        byte[] sharedSecretCompressed = sharedSecret.getPubKey(true);
        Transaction tx = new Transaction();
        for(int k = 0; k <= SilentPaymentUtils.K_MAX; k++) {
            byte[] tkBytes = Utils.taggedHash(SilentPaymentUtils.BIP_0352_SHARED_SECRET_TAG,
                    Utils.concat(sharedSecretCompressed, ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(k).array()));
            ECKey pkm = spendPub.add(ECKey.fromPrivate(new BigInteger(1, tkBytes)), true);
            tx.addOutput(0L, ScriptType.P2TR.getOutputScript(pkm.getPubKeyXCoord()));
        }

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), tweakKey, tx.getOutputs());

        Assertions.assertEquals(SilentPaymentUtils.K_MAX, matches.size());
        Assertions.assertEquals(0, matches.get(0).outputIndex());
        Assertions.assertArrayEquals(Utils.hexToBytes("f438b40179a3c4262de12986c0e6cce0634007cdc79c1dcd3e20b9ebc2e7eef6"), matches.get(0).tweak());
        Assertions.assertEquals(SilentPaymentUtils.K_MAX - 1, matches.getLast().outputIndex());
    }

    @Test
    public void testScanFalsePositiveTweakKey() throws InvalidSilentPaymentException {
        // Use case 0's tweakKey with case 23's outputs (different recipient/output set).
        // The receiver should derive no matches and terminate at the first non-matching k.
        ECKey scanPriv = ECKey.fromPrivate(Utils.hexToBytes(STANDARD_SCAN_PRIV));
        ECKey spendPub = standardSpendPub();
        byte[] tweakKey = Utils.hexToBytes("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004");
        Transaction tx = txWithP2trOutputs("841792c33c9dc6193e76744134125d40add8f2f4a96475f28ba150be032d64e8", "782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338");

        List<SilentPaymentScanMatch> matches = SilentPaymentUtils.scanTransactionOutputs(scanPriv, spendPub, Collections.emptySet(), tweakKey, tx.getOutputs());

        Assertions.assertTrue(matches.isEmpty());
    }
}
