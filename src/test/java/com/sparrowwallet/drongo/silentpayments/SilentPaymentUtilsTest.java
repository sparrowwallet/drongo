package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

public class SilentPaymentUtilsTest {
    @Test
    public void testTweak() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(Utils.hexToBytes("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")));
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(Utils.hexToBytes("48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792")));
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

        Map<HashIndex, TransactionOutput> spentOutputs = new HashMap<>();
        HashIndex hashIndex0 = new HashIndex(transaction.getInputs().getFirst().getOutpoint().getHash(), transaction.getInputs().getFirst().getOutpoint().getIndex());
        TransactionOutput spentOutput0 = new TransactionOutput(new Transaction(), 400L, new Script(Utils.hexToBytes("76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac")));
        HashIndex hashIndex1 = new HashIndex(transaction.getInputs().getLast().getOutpoint().getHash(), transaction.getInputs().getLast().getOutpoint().getIndex());
        TransactionOutput spentOutput1 = new TransactionOutput(new Transaction(), 400L, new Script(Utils.hexToBytes("76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac")));
        spentOutputs.put(hashIndex0, spentOutput0);
        spentOutputs.put(hashIndex1, spentOutput1);

        byte[] tweak = SilentPaymentUtils.getTweak(transaction, spentOutputs);
        Assertions.assertNotNull(tweak);
        Assertions.assertEquals("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004", Utils.bytesToHex(tweak));
    }

    @Test
    public void testTweakReversed() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(Utils.hexToBytes("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")));
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(Utils.hexToBytes("48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792")));
        transaction.addOutput(1000L, ScriptType.P2TR.getOutputScript(ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

        Map<HashIndex, TransactionOutput> spentOutputs = new HashMap<>();
        HashIndex hashIndex0 = new HashIndex(transaction.getInputs().getFirst().getOutpoint().getHash(), transaction.getInputs().getFirst().getOutpoint().getIndex());
        TransactionOutput spentOutput0 = new TransactionOutput(new Transaction(), 400L, new Script(Utils.hexToBytes("76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac")));
        HashIndex hashIndex1 = new HashIndex(transaction.getInputs().getLast().getOutpoint().getHash(), transaction.getInputs().getLast().getOutpoint().getIndex());
        TransactionOutput spentOutput1 = new TransactionOutput(new Transaction(), 400L, new Script(Utils.hexToBytes("76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac")));
        spentOutputs.put(hashIndex0, spentOutput0);
        spentOutputs.put(hashIndex1, spentOutput1);

        byte[] tweak = SilentPaymentUtils.getTweak(transaction, spentOutputs);
        Assertions.assertNotNull(tweak);
        Assertions.assertEquals("024ac253c216532e961988e2a8ce266a447c894c781e52ef6cee902361db960004", Utils.bytesToHex(tweak));
    }

    @Test
    public void testInvalidOutput() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"), 0, new Script(Utils.hexToBytes("483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")));
        transaction.addInput(Sha256Hash.wrap("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"), 0, new Script(Utils.hexToBytes("48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792")));
        transaction.addOutput(1000L, ScriptType.P2WPKH.getOutputScript(ECKey.fromPublicOnly(Utils.hexToBytes("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"))));

        Assertions.assertFalse(SilentPaymentUtils.containsTaprootOutput(transaction));
    }
}
