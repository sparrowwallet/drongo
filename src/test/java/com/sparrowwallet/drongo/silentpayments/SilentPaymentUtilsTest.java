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
import java.util.*;

public class SilentPaymentUtilsTest {
    @Test
    public void testTweak() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(Utils.hexToBytes("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")));
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(Utils.hexToBytes("48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792")));
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

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
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

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
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(ECKey.fromPublicOnly(Utils.hexToBytes("be368e28979d950245d742891ae6064020ba548c1e2e65a639a8bb0675d95cff"))));

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
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(ECKey.fromPublicOnly(Utils.hexToBytes("de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb"))));

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
        BigInteger scanPrivateKey = new BigInteger(1, Utils.hexToBytes("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c"));
        ECKey sharedSecret = tweakKey.multiply(scanPrivateKey, true);
        Assertions.assertEquals("030e7f5ca4bf109fc35c8c2d878f756c891ac04c456cc5f0b05fcec4d3b2b1beb2", Utils.bytesToHex(sharedSecret.getPubKey()));
        byte[] tk = Utils.taggedHash(SilentPaymentUtils.BIP_0352_SHARED_SECRET_TAG, Utils.concat(sharedSecret.getPubKey(true), new byte[4]));
        ECKey tkKey = ECKey.fromPrivate(tk);
        ECKey bSpend = ECKey.fromPublicOnly(ECKey.fromPrivate(Utils.hexToBytes("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3")));
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
        transaction.addOutput(1000L, ScriptType.P2WPKH.getOutputScript(ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

        Assertions.assertFalse(SilentPaymentUtils.containsTaprootOutput(transaction));
    }

    @Test
    public void testSimpleSendTwoInputs() throws InvalidSilentPaymentException {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(Utils.hexToBytes("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")));
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(Utils.hexToBytes("48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792")));
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

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
        BigInteger scanPrivateKey = new BigInteger(1, Utils.hexToBytes("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c"));
        ECKey sharedSecret = tweakKey.multiply(scanPrivateKey, true);
        byte[] tk = Utils.taggedHash(SilentPaymentUtils.BIP_0352_SHARED_SECRET_TAG, Utils.concat(sharedSecret.getPubKey(true), new byte[4]));
        ECKey tkKey = ECKey.fromPrivate(tk);
        ECKey bSpend = ECKey.fromPublicOnly(ECKey.fromPrivate(Utils.hexToBytes("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3")));
        ECKey Pk = bSpend.add(tkKey, true);
        Address address = new P2TRAddress(Pk.getPubKeyXCoord());
        Assertions.assertEquals("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1", Utils.bytesToHex(address.getData()));

        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
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
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

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
        sendWallet.setPolicyType(PolicyType.SINGLE);
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
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSimpleSendTwoInputsSameTransaction() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
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
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("79e71baa2ba3fc66396de3a04f168c7bf24d6870ec88ca877754790c1db357b6", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSimpleSendTwoInputsSameTransactionReversed() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
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
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("f4c2da807f89cb1501f1a77322a895acfb93c28e08ed2724d2beb8e44539ba38", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testOutpointOrderingIndex() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
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
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("a85ef8701394b517a4b35217c4bd37ac01ebeed4b008f8d0879f9e09ba95319c", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientSamePubKey() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
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
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("548ae55c8eec1e736e8d3e520f011f1f42a56d166116ad210b3937599f87f566", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootOnlyEvenY() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
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
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootOnlyMixedY() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
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
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf26b99f1", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootEvenYAndNonTaproot() throws InvalidSilentPaymentException {
        Wallet taprootWallet = new Wallet();
        taprootWallet.setPolicyType(PolicyType.SINGLE);
        taprootWallet.setScriptType(ScriptType.P2TR);
        Map<WalletNode, ECKey> taprootPrivateKeys = new LinkedHashMap<>();

        Wallet segwitWallet = new Wallet();
        segwitWallet.setPolicyType(PolicyType.SINGLE);
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
        taprootWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, taprootWallet.getKeystores(), 1));

        TestKeystore segwitKeystore = new TestKeystore(segwitPrivateKeys);
        segwitWallet.getKeystores().add(segwitKeystore);
        segwitWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, segwitWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("30523cca96b2a9ae3c98beb5e60f7d190ec5bc79b2d11a0b2d4d09a608c448f0", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootOddYAndNonTaproot() throws InvalidSilentPaymentException {
        Wallet taprootWallet = new Wallet();
        taprootWallet.setPolicyType(PolicyType.SINGLE);
        taprootWallet.setScriptType(ScriptType.P2TR);
        Map<WalletNode, ECKey> taprootPrivateKeys = new LinkedHashMap<>();

        Wallet segwitWallet = new Wallet();
        segwitWallet.setPolicyType(PolicyType.SINGLE);
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
        taprootWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, taprootWallet.getKeystores(), 1));

        TestKeystore segwitKeystore = new TestKeystore(segwitPrivateKeys);
        segwitWallet.getKeystores().add(segwitKeystore);
        segwitWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, segwitWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.computeOutputAddresses(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("359358f59ee9e9eec3f00bdf4882570fd5c182e451aa2650b788544aff012a3a", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testMultipleOutputsSameRecipient() throws InvalidSilentPaymentException {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
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
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

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
        sendWallet.setPolicyType(PolicyType.SINGLE);
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
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

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
}
