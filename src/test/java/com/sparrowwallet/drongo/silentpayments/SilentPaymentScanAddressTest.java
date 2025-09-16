package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.MnemonicException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SilentPaymentScanAddressTest {
    @Test
    public void testEncode() {
        ECKey scanPrivateKey = ECKey.fromPrivate(Utils.hexToBytes("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c"));
        ECKey spendPrivateKey = ECKey.fromPrivate(Utils.hexToBytes("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3"));

        SilentPaymentScanAddress silentPaymentScanAddress = SilentPaymentScanAddress.from(scanPrivateKey, ECKey.fromPublicOnly(spendPrivateKey));
        Assertions.assertEquals("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv", silentPaymentScanAddress.getAddress());
    }

    @Test
    public void testEncodeFromSeed() throws MnemonicException {
        Network.set(Network.TESTNET);
        DeterministicSeed seed = new DeterministicSeed("life life life life life life life life life life life life", "", 0, DeterministicSeed.Type.BIP39);
        SilentPaymentScanAddress silentPaymentScanAddress = SilentPaymentScanAddress.from(seed, 0);
        Assertions.assertEquals("tsp1qq0grgkzt7uwfst33pyge7k9mrkag0r9vrklc695n0pw7kwwc7qddqqley3n2a6z8q7vhkhzedtzj5kr86hv6fhh0zvu2j9tjrrxa4ye3acuv6f3q", silentPaymentScanAddress.getAddress());
        Assertions.assertEquals("36dc57ced5f4a76059947802f094ea40d0c11c74d444a1e7d3ea5e74b8d83d45", Utils.bytesToHex(silentPaymentScanAddress.getScanKey().getPrivKeyBytes()));
        Assertions.assertEquals("03f92466aee84707997b5c596ac52a5867d5d9a4deef1338a9157218cdda9331ee", Utils.bytesToHex(silentPaymentScanAddress.getSpendKey().getPubKey()));
    }

    @Test
    public void testEncodeFromSeed2() throws MnemonicException {
        Network.set(Network.TESTNET);
        DeterministicSeed seed = new DeterministicSeed("resist cube wrap sleep catalog shadow door scale stage rail script observe", "", 0, DeterministicSeed.Type.BIP39);
        SilentPaymentScanAddress silentPaymentScanAddress = SilentPaymentScanAddress.from(seed, 0);
        Assertions.assertEquals("tsp1qqgksl44sjwjkedsmrfmf2xqsnyt2njtjp5plk2kzjlnd9el2n76awqe5j974lvkf2utv7nrg0eaug55z86n6n3v4e9alnftdzgqk6pqmm5dphvxn", silentPaymentScanAddress.getAddress());
    }

    @Test
    public void testLabels() {
        ECKey scanPrivateKey = ECKey.fromPrivate(Utils.hexToBytes("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c"));
        ECKey spendPrivateKey = ECKey.fromPrivate(Utils.hexToBytes("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3"));

        SilentPaymentScanAddress unlabelled = SilentPaymentScanAddress.from(scanPrivateKey, ECKey.fromPublicOnly(spendPrivateKey));
        Assertions.assertEquals("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv", unlabelled.getAddress());
        Assertions.assertEquals("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq", unlabelled.getLabelledAddress(2).getAddress());
        Assertions.assertEquals("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqsg59z2rppn4qlkx0yz9sdltmjv3j8zgcqadjn4ug98m3t6plujsq9qvu5n", unlabelled.getLabelledAddress(3).getAddress());
        Assertions.assertEquals("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5", unlabelled.getLabelledAddress(1001337).getAddress());
    }

    @Test
    public void testChange() {
        ECKey scanPrivateKey = ECKey.fromPrivate(Utils.hexToBytes("11b7a82e06ca2648d5fded2366478078ec4fc9dc1d8ff487518226f229d768fd"));
        ECKey spendPrivateKey = ECKey.fromPrivate(Utils.hexToBytes("b8f87388cbb41934c50daca018901b00070a5ff6cc25a7e9e716a9d5b9e4d664"));

        SilentPaymentScanAddress unlabelled = SilentPaymentScanAddress.from(scanPrivateKey, ECKey.fromPublicOnly(spendPrivateKey));
        Assertions.assertEquals("sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqauj52ymtc4xdkmx3tgyhrsemg2g3303xk2gtzfy8h8ejet8fz8jcw23zua", unlabelled.getAddress());
        Assertions.assertEquals("sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqlv6saelkk5snl4wfutyxrchpzzwm8rjp3z6q7apna59z9huq4x754e5atr", unlabelled.getChangeAddress().getAddress());
        Assertions.assertEquals("03bc95144daf15336db3456825c70ced0a4462f89aca42c4921ee7ccb2b3a44796", Utils.bytesToHex(spendPrivateKey.getPubKey()));
        Assertions.assertEquals("03ecd43b9fdad484ff57278b21878b844276ce390622d03dd0cfb4288b7e02a6f5", Utils.bytesToHex(unlabelled.getChangeAddress().getSpendKey().getPubKey()));
    }

    @AfterEach
    public void tearDown() {
        Network.set(null);
    }
}
