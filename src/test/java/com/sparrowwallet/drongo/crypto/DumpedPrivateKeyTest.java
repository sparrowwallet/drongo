package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class DumpedPrivateKeyTest {
    private static final String COMPRESSED_WIF = "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP";
    private static final String UNCOMPRESSED_WIF = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR";

    @Test
    public void testCompressedRoundTrip() {
        DumpedPrivateKey parsed = DumpedPrivateKey.fromBase58(COMPRESSED_WIF);
        Assertions.assertTrue(parsed.getKey().isCompressed());
        Assertions.assertEquals(COMPRESSED_WIF, parsed.toBase58());
        Assertions.assertEquals(COMPRESSED_WIF, parsed.getKey().getPrivateKeyEncoded().toBase58());
    }

    @Test
    public void testUncompressedRoundTrip() {
        DumpedPrivateKey parsed = DumpedPrivateKey.fromBase58(UNCOMPRESSED_WIF);
        Assertions.assertFalse(parsed.getKey().isCompressed());
        Assertions.assertEquals(UNCOMPRESSED_WIF, parsed.toBase58());
        Assertions.assertEquals(UNCOMPRESSED_WIF, parsed.getKey().getPrivateKeyEncoded().toBase58());
    }

    @Test
    public void testKeyMatchesRegardlessOfConstruction() {
        for(String wif : new String[] {COMPRESSED_WIF, UNCOMPRESSED_WIF}) {
            DumpedPrivateKey parsed = DumpedPrivateKey.fromBase58(wif);
            DumpedPrivateKey encoded = parsed.getKey().getPrivateKeyEncoded();
            Assertions.assertEquals(Utils.bytesToHex(parsed.getKey().getPubKey()), Utils.bytesToHex(encoded.getKey().getPubKey()));
            Assertions.assertEquals(parsed, encoded);
            Assertions.assertEquals(parsed.hashCode(), encoded.hashCode());
        }
    }

    @Test
    public void testCompressedAndUncompressedDifferDespiteSharedScalar() {
        //These two BIP38 vectors are the same 32 byte scalar, so only the compression marker separates them
        ECKey compressed = DumpedPrivateKey.fromBase58(COMPRESSED_WIF).getKey();
        ECKey uncompressed = DumpedPrivateKey.fromBase58(UNCOMPRESSED_WIF).getKey();
        Assertions.assertEquals(compressed.getPrivKey(), uncompressed.getPrivKey());
        Assertions.assertNotEquals(Utils.bytesToHex(compressed.getPubKey()), Utils.bytesToHex(uncompressed.getPubKey()));
    }
}
