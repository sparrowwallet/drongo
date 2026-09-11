package com.sparrowwallet.drongo.uri;

import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.silentpayments.SilentPayment;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Payment;
import com.sparrowwallet.drongo.wallet.Wallet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class BitcoinUriTest {
    private static final String ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    private static final String SP_ADDRESS = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";

    @Test
    public void fallbackAddressIsPreferredOnlyWhereSilentPaymentsCannotBeSent() throws BitcoinURIParseException {
        BitcoinURI bitcoinURI = new BitcoinURI("bitcoin:" + ADDRESS + "?sp=" + SP_ADDRESS);
        Assertions.assertNotNull(bitcoinURI.getAddress());
        Assertions.assertNotNull(bitcoinURI.getSilentPaymentAddress());

        //The address in the body is a fallback for a sender that cannot pay the silent payment address in the query
        Payment fallbackPayment = bitcoinURI.toPayment(buildWallet(PolicyType.MULTI_HD, ScriptType.P2WSH));
        Assertions.assertFalse(fallbackPayment instanceof SilentPayment);
        Assertions.assertEquals(ADDRESS, fallbackPayment.getAddress().toString());

        Payment silentPayment = bitcoinURI.toPayment(buildWallet(PolicyType.SINGLE_HD, ScriptType.P2WPKH));
        Assertions.assertInstanceOf(SilentPayment.class, silentPayment);
        Assertions.assertEquals(SP_ADDRESS, ((SilentPayment)silentPayment).getSilentPaymentAddress().toString());

        //Without a wallet to ask, the fallback is taken as it was before the sending wallet could be considered
        Assertions.assertFalse(bitcoinURI.toPayment(null) instanceof SilentPayment);
    }

    @Test
    public void silentPaymentAddressIsTakenWithoutAFallback() throws BitcoinURIParseException {
        BitcoinURI bitcoinURI = new BitcoinURI("bitcoin:?sp=" + SP_ADDRESS);
        Assertions.assertNull(bitcoinURI.getAddress());

        //With nothing to fall back to, a wallet that cannot send silent payments is still given the silent payment address to refuse
        Assertions.assertInstanceOf(SilentPayment.class, bitcoinURI.toPayment(buildWallet(PolicyType.MULTI_HD, ScriptType.P2WSH)));
        Assertions.assertInstanceOf(SilentPayment.class, bitcoinURI.toPayment(null));
    }

    private Wallet buildWallet(PolicyType policyType, ScriptType scriptType) {
        Wallet wallet = new Wallet("test");
        wallet.setPolicyType(policyType);
        wallet.setScriptType(scriptType);
        wallet.getKeystores().add(new Keystore());
        if(policyType == PolicyType.MULTI_HD) {
            wallet.getKeystores().add(new Keystore());
        }

        return wallet;
    }

    @Test
    public void testSamourai() throws BitcoinURIParseException {
        String uri = "bitcoin:BC1QT4NRM47695YWDG9N30N68JARMXRJNKFMR36994?amount=0,001";
        BitcoinURI bitcoinURI = new BitcoinURI(uri);

        Assertions.assertEquals("BC1QT4NRM47695YWDG9N30N68JARMXRJNKFMR36994".toLowerCase(Locale.ROOT), bitcoinURI.getAddress().toString());
        Assertions.assertEquals(Long.valueOf(100000), bitcoinURI.getAmount());
    }

    @Test
    public void acceptsHttpsPayjoinUrl() throws BitcoinURIParseException {
        BitcoinURI bitcoinURI = payjoinUri("https://example.com/payjoin");
        Assertions.assertNotNull(bitcoinURI.getPayjoinUrl());
        Assertions.assertEquals("https://example.com/payjoin", bitcoinURI.getPayjoinUrl().toString());
    }

    @Test
    public void acceptsHttpOnionPayjoinUrl() throws BitcoinURIParseException {
        BitcoinURI bitcoinURI = payjoinUri("http://abcdefghijklmnopqrstuvwxyzabcdefghijklmnop.onion/payjoin");
        Assertions.assertNotNull(bitcoinURI.getPayjoinUrl());
        Assertions.assertEquals("http://abcdefghijklmnopqrstuvwxyzabcdefghijklmnop.onion/payjoin", bitcoinURI.getPayjoinUrl().toString());
    }

    @Test
    public void rejectsNonHttpOnionPayjoinUrl() throws BitcoinURIParseException {
        BitcoinURI bitcoinURI = payjoinUri("file://abcdefghijklmnopqrstuvwxyzabcdefghijklmnop.onion/payjoin");
        Assertions.assertNull(bitcoinURI.getPayjoinUrl());
    }

    @Test
    public void rejectsMalformedPayjoinUrl() throws BitcoinURIParseException {
        BitcoinURI bitcoinURI = payjoinUri("payjoin");
        Assertions.assertNull(bitcoinURI.getPayjoinUrl());
    }

    @Test
    public void rejectsExponentAmount() {
        Assertions.assertThrows(OptionalFieldValidationException.class, () -> amountUri("1e2"));
        Assertions.assertThrows(OptionalFieldValidationException.class, () -> amountUri("1E-8"));
    }

    @Test
    public void rejectsNonDecimalAmount() {
        Assertions.assertThrows(OptionalFieldValidationException.class, () -> amountUri("+1"));
        Assertions.assertThrows(OptionalFieldValidationException.class, () -> amountUri("-1"));
        Assertions.assertThrows(OptionalFieldValidationException.class, () -> amountUri("1.2.3"));
        Assertions.assertThrows(OptionalFieldValidationException.class, () -> amountUri("\u0663"));
    }

    @Test
    public void acceptsDecimalAmount() throws BitcoinURIParseException {
        Assertions.assertEquals(Long.valueOf(12345678), amountUri("0.12345678").getAmount());
        Assertions.assertEquals(Long.valueOf(50000000), amountUri("0,5").getAmount());
        Assertions.assertEquals(Long.valueOf(100000000), amountUri("1.").getAmount());
        Assertions.assertEquals(Long.valueOf(50000000), amountUri(".5").getAmount());
    }

    @Test
    public void rejectsTooManyDecimalPlaces() {
        Assertions.assertThrows(OptionalFieldValidationException.class, () -> amountUri("0.123456789"));
    }

    private static BitcoinURI amountUri(String amount) throws BitcoinURIParseException {
        return new BitcoinURI("bitcoin:" + ADDRESS + "?amount=" + amount);
    }

    private static BitcoinURI payjoinUri(String payjoinUrl) throws BitcoinURIParseException {
        return new BitcoinURI("bitcoin:" + ADDRESS + "?pj=" + URLEncoder.encode(payjoinUrl, StandardCharsets.UTF_8));
    }
}
