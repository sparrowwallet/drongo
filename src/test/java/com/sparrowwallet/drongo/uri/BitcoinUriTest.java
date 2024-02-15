package com.sparrowwallet.drongo.uri;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Locale;

public class BitcoinUriTest {
    @Test
    public void testSamourai() throws BitcoinURIParseException {
        String uri = "bitcoin:BC1QT4NRM47695YWDG9N30N68JARMXRJNKFMR36994?amount=0,001";
        BitcoinURI bitcoinURI = new BitcoinURI(uri);

        Assertions.assertEquals("BC1QT4NRM47695YWDG9N30N68JARMXRJNKFMR36994".toLowerCase(Locale.ROOT), bitcoinURI.getAddress().toString());
        Assertions.assertEquals(Long.valueOf(100000), bitcoinURI.getAmount());
    }
}
