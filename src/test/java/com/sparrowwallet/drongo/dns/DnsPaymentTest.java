package com.sparrowwallet.drongo.dns;

import com.sparrowwallet.drongo.uri.BitcoinURI;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Optional;

public class DnsPaymentTest {
    @Test
    public void validNames() {
        Assertions.assertEquals(Optional.of("craig@sparrowwallet.com"), DnsPayment.getHrn("craig@sparrowwallet.com"));
        Assertions.assertEquals(Optional.of("craig@sparrowwallet.com"), DnsPayment.getHrn("₿craig@sparrowwallet.com"));
        Assertions.assertTrue(DnsPayment.getHrn("first.last_1-x@pay.example.co").isPresent());
    }

    @Test
    public void invalidNames() {
        Assertions.assertTrue(DnsPayment.getHrn("bitcoin:bc1qwthe43xeuasklclq4kvhreluv3hu92rzej42js?x=y@pay.example.com").isEmpty());
        Assertions.assertTrue(DnsPayment.getHrn("craig@sparrowwallet.com.").isEmpty());
        Assertions.assertTrue(DnsPayment.getHrn("cr aig@sparrowwallet.com").isEmpty());
        Assertions.assertTrue(DnsPayment.getHrn("craig@sparrowwallet").isEmpty());
        Assertions.assertTrue(DnsPayment.getHrn("a@b@sparrowwallet.com").isEmpty());
        Assertions.assertThrows(IllegalArgumentException.class, () -> new DnsPaymentResolver("bitcoin:bc1qwthe43xeuasklclq4kvhreluv3hu92rzej42js?x=y@pay.example.com"));
    }

    @Test
    public void otherNetworkSilentPaymentAddress() throws Exception {
        String hrp = BitcoinURI.FIELD_SILENT_PAYMENTS_ADDRESS;
        String otherHrp = hrp.equals("sp") ? "tsp" : "sp";
        Assertions.assertTrue(new DnsPayment("craig@sparrowwallet.com", new BitcoinURI("bitcoin:?" + otherHrp + "=" + otherHrp + "1q"), new byte[0]).hasOtherNetworkSilentPaymentAddress());
        Assertions.assertFalse(new DnsPayment("craig@sparrowwallet.com", new BitcoinURI("bitcoin:?" + hrp + "=" + hrp + "1q"), new byte[0]).hasOtherNetworkSilentPaymentAddress());
        Assertions.assertFalse(new DnsPayment("craig@sparrowwallet.com", new BitcoinURI("bitcoin:?label=x"), new byte[0]).hasOtherNetworkSilentPaymentAddress());
    }
}
