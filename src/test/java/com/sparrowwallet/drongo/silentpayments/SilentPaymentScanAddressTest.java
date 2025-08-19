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

    @AfterEach
    public void tearDown() {
        Network.set(null);
    }
}
