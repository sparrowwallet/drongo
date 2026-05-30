package com.sparrowwallet.drongo.uri;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class BitcoinUriTest {
    private static final String ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

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

    private static BitcoinURI payjoinUri(String payjoinUrl) throws BitcoinURIParseException {
        return new BitcoinURI("bitcoin:" + ADDRESS + "?pj=" + URLEncoder.encode(payjoinUrl, StandardCharsets.UTF_8));
    }
}
