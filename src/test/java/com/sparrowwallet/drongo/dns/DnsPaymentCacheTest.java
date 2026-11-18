package com.sparrowwallet.drongo.dns;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.silentpayments.SilentPayment;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentAddress;
import com.sparrowwallet.drongo.uri.BitcoinURI;
import com.sparrowwallet.drongo.wallet.Payment;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class DnsPaymentCacheTest {
    @Test
    public void paymentLookupMatchesRecipient() throws Exception {
        Address paid = Address.fromString("bc1qwthe43xeuasklclq4kvhreluv3hu92rzej42js");
        Address other = Address.fromString("bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l");

        DnsPayment otherPayment = new DnsPayment("other@example.com", new BitcoinURI("bitcoin:" + other), new byte[0]);
        DnsPaymentCache.putDnsPayment(paid, otherPayment);
        Assertions.assertNull(DnsPaymentCache.getDnsPayment(new Payment(paid, "label", 1000, false)));

        DnsPayment paidPayment = new DnsPayment("paid@example.com", new BitcoinURI("bitcoin:" + paid), new byte[0]);
        DnsPaymentCache.putDnsPayment(paid, paidPayment);
        Assertions.assertEquals(paidPayment, DnsPaymentCache.getDnsPayment(new Payment(paid, "label", 1000, false)));
    }

    @Test
    public void silentPaymentLookupMatchesRecipient() throws Exception {
        SilentPaymentAddress paid = SilentPaymentAddress.from("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv");
        SilentPaymentAddress other = SilentPaymentAddress.from("sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn");

        DnsPayment otherPayment = new DnsPayment("other@example.com", new BitcoinURI("bitcoin:?sp=" + other.getAddress()), new byte[0]);
        DnsPaymentCache.putDnsPayment(paid, otherPayment);
        Assertions.assertNull(DnsPaymentCache.getDnsPayment(new SilentPayment(paid, "label", 1000, false)));

        DnsPayment paidPayment = new DnsPayment("paid@example.com", new BitcoinURI("bitcoin:?sp=" + paid.getAddress()), new byte[0]);
        DnsPaymentCache.putDnsPayment(paid, paidPayment);
        Assertions.assertEquals(paidPayment, DnsPaymentCache.getDnsPayment(new SilentPayment(paid, "label", 1000, false)));
    }
}
