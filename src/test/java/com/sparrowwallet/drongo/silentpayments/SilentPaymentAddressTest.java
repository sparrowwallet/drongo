package com.sparrowwallet.drongo.silentpayments;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SilentPaymentAddressTest {
    @Test
    public void testDecode() {
        ECKey scanPrivateKey = ECKey.fromPrivate(Utils.hexToBytes("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c"));
        ECKey spendPrivateKey = ECKey.fromPrivate(Utils.hexToBytes("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3"));

        SilentPaymentAddress silentPaymentAddress = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        Assertions.assertEquals(ECKey.fromPublicOnly(scanPrivateKey), silentPaymentAddress.getScanKey());
        Assertions.assertEquals(ECKey.fromPublicOnly(spendPrivateKey), silentPaymentAddress.getSpendKey());
    }
}
