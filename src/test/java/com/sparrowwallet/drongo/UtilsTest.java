package com.sparrowwallet.drongo;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;

public class UtilsTest {
    @Test
    public void isSecureUrlAcceptsHttps() throws Exception {
        Assertions.assertTrue(Utils.isSecureUrl(new URI("https://example.com/callback")));
    }

    @Test
    public void isSecureUrlAcceptsUppercaseHttps() throws Exception {
        Assertions.assertTrue(Utils.isSecureUrl(new URI("HTTPS://example.com/callback")));
    }

    @Test
    public void isSecureUrlAcceptsHttpOnion() throws Exception {
        Assertions.assertTrue(Utils.isSecureUrl(new URI("http://abcdefghijklmnopqrstuvwxyzabcdefghijklmnop.onion/callback")));
    }

    @Test
    public void isSecureUrlRejectsHttpClearnet() throws Exception {
        Assertions.assertFalse(Utils.isSecureUrl(new URI("http://example.com/callback")));
    }

    @Test
    public void isSecureUrlRejectsNonHttpOnion() throws Exception {
        Assertions.assertFalse(Utils.isSecureUrl(new URI("ftp://abcdefghijklmnopqrstuvwxyzabcdefghijklmnop.onion/callback")));
    }

    @Test
    public void isSecureUrlRejectsOpaqueHttps() throws Exception {
        Assertions.assertFalse(Utils.isSecureUrl(new URI("https:opaque")));
    }

    @Test
    public void isSecureUrlRejectsSchemeless() throws Exception {
        Assertions.assertFalse(Utils.isSecureUrl(new URI("callback")));
    }

    @Test
    public void isSecureUrlRejectsNull() {
        Assertions.assertFalse(Utils.isSecureUrl(null));
    }
}
