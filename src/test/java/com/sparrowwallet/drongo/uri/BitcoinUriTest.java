package com.sparrowwallet.drongo.uri;

import org.junit.Assert;
import org.junit.Test;

public class BitcoinUriTest {
    @Test
    public void testSamourai() throws BitcoinURIParseException {
        String uri = "groestlcoin:BC1QT4NRM47695YWDG9N30N68JARMXRJNKFMR36994?amount=0,001";
        BitcoinURI bitcoinURI = new BitcoinURI(uri);

        Assert.assertEquals("BC1QT4NRM47695YWDG9N30N68JARMXRJNKFMR36994".toLowerCase(), bitcoinURI.getAddress().toString());
        Assert.assertEquals(Long.valueOf(100000), bitcoinURI.getAmount());
    }
}
