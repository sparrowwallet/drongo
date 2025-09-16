package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.wallet.BlockTransactionHashIndex;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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
    public void testInvalidOutput() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(Utils.hexToBytes("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")));
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(Utils.hexToBytes("48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792")));
        transaction.addOutput(1000L, ScriptType.P2WPKH.getOutputScript(ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

        Assertions.assertFalse(SilentPaymentUtils.containsTaprootOutput(transaction));
    }

    @Test
    public void testSimpleSendTwoInputs() {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 0, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, null, null, 0, 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSimpleSendTwoInputsReversed() {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, null, null, 0, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 0, 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSimpleSendTwoInputsSameTransaction() {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 3, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 7, 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("79e71baa2ba3fc66396de3a04f168c7bf24d6870ec88ca877754790c1db357b6", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSimpleSendTwoInputsSameTransactionReversed() {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, null, null, 7, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, null, null, 3, 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("f4c2da807f89cb1501f1a77322a895acfb93c28e08ed2724d2beb8e44539ba38", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testOutpointOrderingIndex() {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 1, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 256, 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("a85ef8701394b517a4b35217c4bd37ac01ebeed4b008f8d0879f9e09ba95319c", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientSamePubKey() {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 0, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, null, null, 0, 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("548ae55c8eec1e736e8d3e520f011f1f42a56d166116ad210b3937599f87f566", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootOnlyEvenY() {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
        sendWallet.setScriptType(ScriptType.P2TR);
        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 0, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, null, null, 0, 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("fc8716a97a48ba9a05a98ae47b5cd201a25a7fd5d8b73c203c5f7b6b6b3b6ad7"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootOnlyMixedY() {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
        sendWallet.setScriptType(ScriptType.P2TR);
        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 0, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, null, null, 0, 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("1d37787c2b7116ee983e9f9c13269df29091b391c04db94239e0d2bc2182c3bf"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress, "", 0, false));

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf26b99f1", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootEvenYAndNonTaproot() {
        Wallet taprootWallet = new Wallet();
        taprootWallet.setPolicyType(PolicyType.SINGLE);
        taprootWallet.setScriptType(ScriptType.P2TR);
        Map<WalletNode, ECKey> taprootPrivateKeys = new LinkedHashMap<>();

        Wallet segwitWallet = new Wallet();
        segwitWallet.setPolicyType(PolicyType.SINGLE);
        segwitWallet.setScriptType(ScriptType.P2WPKH);
        Map<WalletNode, ECKey> segwitPrivateKeys = new LinkedHashMap<>();

        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(taprootWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 0, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        taprootPrivateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(segwitWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, null, null, 0, 0);
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

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("30523cca96b2a9ae3c98beb5e60f7d190ec5bc79b2d11a0b2d4d09a608c448f0", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testSingleRecipientTaprootOddYAndNonTaproot() {
        Wallet taprootWallet = new Wallet();
        taprootWallet.setPolicyType(PolicyType.SINGLE);
        taprootWallet.setScriptType(ScriptType.P2TR);
        Map<WalletNode, ECKey> taprootPrivateKeys = new LinkedHashMap<>();

        Wallet segwitWallet = new Wallet();
        segwitWallet.setPolicyType(PolicyType.SINGLE);
        segwitWallet.setScriptType(ScriptType.P2WPKH);
        Map<WalletNode, ECKey> segwitPrivateKeys = new LinkedHashMap<>();

        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(taprootWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 0, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("1d37787c2b7116ee983e9f9c13269df29091b391c04db94239e0d2bc2182c3bf"));
        utxos.put(ref0, walletNode0);
        taprootPrivateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(segwitWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, null, null, 0, 0);
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

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
        Assertions.assertEquals(1, silentPayments.size());
        Assertions.assertEquals("359358f59ee9e9eec3f00bdf4882570fd5c182e451aa2650b788544aff012a3a", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
    }

    @Test
    public void testMultipleOutputsSameRecipient() {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 0, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, null, null, 0, 0);
        ECKey privKey1 = ECKey.fromPrivate(Utils.hexToBytes("0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a"));
        utxos.put(ref1, walletNode1);
        privateKeys.put(walletNode1, privKey1);

        TestKeystore sendKeystore = new TestKeystore(privateKeys);
        sendWallet.getKeystores().add(sendKeystore);
        sendWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, ScriptType.P2WPKH, sendWallet.getKeystores(), 1));

        SilentPaymentAddress silentPaymentAddress0 = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        SilentPaymentAddress silentPaymentAddress1 = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        List<SilentPayment> silentPayments = List.of(new SilentPayment(silentPaymentAddress0, "First", 0, false), new SilentPayment(silentPaymentAddress1, "Second", 0, false));

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
        Assertions.assertEquals(2, silentPayments.size());
        Assertions.assertEquals("First", silentPayments.getFirst().getLabel());
        Assertions.assertEquals("f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac", Utils.bytesToHex(silentPayments.getFirst().getAddress().getData()));
        Assertions.assertEquals("Second", silentPayments.getLast().getLabel());
        Assertions.assertEquals("e976a58fbd38aeb4e6093d4df02e9c1de0c4513ae0c588cef68cda5b2f8834ca", Utils.bytesToHex(silentPayments.getLast().getAddress().getData()));
    }

    @Test
    public void testMultipleOutputsMultipleRecipients() {
        Wallet sendWallet = new Wallet();
        sendWallet.setPolicyType(PolicyType.SINGLE);
        sendWallet.setScriptType(ScriptType.P2WPKH);
        Map<BlockTransactionHashIndex, WalletNode> utxos = new LinkedHashMap<>();
        Map<WalletNode, ECKey> privateKeys = new LinkedHashMap<>();

        WalletNode walletNode0 = new WalletNode(sendWallet, "/0/0");
        BlockTransactionHashIndex ref0 = new BlockTransactionHashIndex(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, null, null, 0, 0);
        ECKey privKey0 = ECKey.fromPrivate(Utils.hexToBytes("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"));
        utxos.put(ref0, walletNode0);
        privateKeys.put(walletNode0, privKey0);

        WalletNode walletNode1 = new WalletNode(sendWallet, "/0/1");
        BlockTransactionHashIndex ref1 = new BlockTransactionHashIndex(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, null, null, 0, 0);
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

        SilentPaymentUtils.updateSilentPayments(silentPayments, utxos);
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
