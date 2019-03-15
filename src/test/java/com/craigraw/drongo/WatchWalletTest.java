package com.craigraw.drongo;

import org.junit.Assert;
import org.junit.Test;

public class WatchWalletTest {

    @Test
    public void electrumP2PKH() {
        WatchWallet wallet = new WatchWallet("", "xpub661MyMwAqRbcFT5HwyRoP5hebbeRDvy2RGDTH2uxFyDPaf5FLtu4njuishddViQxTABZKzoWKuwpy6MsgfPvTw9pKnRGDL5eBxDej9kF54Z");

        Assert.assertEquals("1QEjP9f7KRtJobfwmRuykpLjaR5QchGo8q", wallet.getReceivingAddress(0).toString());
        Assert.assertEquals("17kCok3XAUHyL6kjzBF44e1YuzMmRXPuu5", wallet.getReceivingAddress(1).toString());
        Assert.assertEquals("1Dh3Lofy2cFdEQ2rk4Eq6fbPeQQ63pDdRN", wallet.getChangeAddress(0).toString());
    }

    @Test
    public void iancolemanP2PKH() {
        WatchWallet wallet = new WatchWallet("", "xpub6EEznxrqoN5HUXfD3QC3B8Vjw8Lj9UnRj17uTzNaBnEYN5xgwe6Un46Z443sSTBP2bzLZuDzygkdD1FtVWSexFmg4yAuCTxE2HxXFtz541z");

        Assert.assertEquals("179cMrkiyx6zD2E1sqBAQLg1SQPAS5vjQW", wallet.getReceivingAddress(0).toString());
        Assert.assertEquals("1GdWCzdt5oDYh5n1qeZQCxg5rQKVTuTMJg", wallet.getReceivingAddress(1).toString());
    }

    @Test
    public void electrumP2WPKH() {
        WatchWallet wallet = new WatchWallet("", "zpub6njbcfTHEfK4U96Z8dBaTULdb1LGWMtj73yYZ76kfmE9nuf3KhNSsXfzDefz5KV6TreWjnQbgvnSmSttudzTugesV2HFunYu7gWYJUD4eoR");

        Assert.assertEquals("bc1q4s5v0u9qmmcp25mnr3mfzhyftjzw8mccqawmwf", wallet.getReceivingAddress(0).toString());
        Assert.assertEquals("bc1qffy90ge6wljh53t07q4al2pgsmuqgy48wrk8wq", wallet.getReceivingAddress(1).toString());
        Assert.assertEquals("bc1q87fg9yjxratt4hemjn0m4re97n2p39ssq5xhv4", wallet.getChangeAddress(0).toString());
    }

    @Test
    public void iancolemanP2SHP2WPKH() {
        WatchWallet wallet = new WatchWallet("", "ypub6Zken22QbjfomRUXki5v4ndP6T1DEtaBhGGZBvR4ocoooM44dFmnF8DyFmvcK76TKnuvdFfaPnicVvTAPdqEcbuEfKEqfnRoUjSkTB4u1os");

        Assert.assertEquals("34SgiHwNwJt3nYCVUQcgJWhefVRBZ4aSHf", wallet.getReceivingAddress(0).toString());
        Assert.assertEquals("3MgPnbF6UYM3FBhZWXoL2ebLPEa3zCCXLh", wallet.getReceivingAddress(1).toString());
    }

    @Test
    public void bip84P2WPKH() {
        WatchWallet wallet = new WatchWallet("", "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs");

        Assert.assertEquals("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", wallet.getReceivingAddress(0).toString());
        Assert.assertEquals("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", wallet.getReceivingAddress(1).toString());
        Assert.assertEquals("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", wallet.getChangeAddress(0).toString());
    }

    @Test
    public void redditP2SHP2WPKH() {
        WatchWallet wallet = new WatchWallet("", "ypub6XiW9nhToS1gjVsFKzgmtWZuqo6V1YY7xaCns37aR3oYhFyAsTehAqV1iW2UCNtgWFQFkz3aNSZZbkfe5d1tD8MzjZuFJQn2XnczsxtjoXr");

        Assert.assertEquals("34TBBnwqv338BT6BVnTKqziFq8HWY6BNbw", wallet.getReceivingAddress(0).toString());
        Assert.assertEquals("35Jhf9LGCpb1ihJjWH7uLZ8othr1diuspS", wallet.getChangeAddress(0).toString());
    }
}
