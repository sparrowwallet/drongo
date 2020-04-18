package com.sparrowwallet.drongo;

import org.junit.Assert;
import org.junit.Test;

public class OutputDescriptorTest {

    @Test
    public void electrumP2PKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("xpub661MyMwAqRbcFT5HwyRoP5hebbeRDvy2RGDTH2uxFyDPaf5FLtu4njuishddViQxTABZKzoWKuwpy6MsgfPvTw9pKnRGDL5eBxDej9kF54Z");
        Assert.assertEquals("pkh(xpub661MyMwAqRbcFT5HwyRoP5hebbeRDvy2RGDTH2uxFyDPaf5FLtu4njuishddViQxTABZKzoWKuwpy6MsgfPvTw9pKnRGDL5eBxDej9kF54Z/0/*)", descriptor.toString());
    }

    @Test
    public void iancolemanP2PKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("xpub6EEznxrqoN5HUXfD3QC3B8Vjw8Lj9UnRj17uTzNaBnEYN5xgwe6Un46Z443sSTBP2bzLZuDzygkdD1FtVWSexFmg4yAuCTxE2HxXFtz541z/*");
        Assert.assertEquals("pkh(xpub6EEznxrqoN5HUXfD3QC3B8Vjw8Lj9UnRj17uTzNaBnEYN5xgwe6Un46Z443sSTBP2bzLZuDzygkdD1FtVWSexFmg4yAuCTxE2HxXFtz541z/*)", descriptor.toString());
    }

    @Test
    public void electrumP2WPKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("zpub6njbcfTHEfK4U96Z8dBaTULdb1LGWMtj73yYZ76kfmE9nuf3KhNSsXfzDefz5KV6TreWjnQbgvnSmSttudzTugesV2HFunYu7gWYJUD4eoR");
        Assert.assertEquals("wpkh(xpub69551L7SwJE6mYiKTucL3J9dF53Nd7ujGpw6zKJyukUPgi2apP3KdQMiBEkp5WBFeaQuEqDUmc5LzsfmUFASKDHfkLtQjxuvaEPFXNDF4Kg/0/*)", descriptor.toString());
    }

    @Test
    public void iancolemanP2SHP2WPKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("ypub6Zken22QbjfomRUXki5v4ndP6T1DEtaBhGGZBvR4ocoooM44dFmnF8DyFmvcK76TKnuvdFfaPnicVvTAPdqEcbuEfKEqfnRoUjSkTB4u1os/*");
        Assert.assertEquals("sh(wpkh(xpub6EvPUMMVT48Kv8HQvMJHrhXsvUrmJGagn9kLQXXBRcRvkFEqNbcDd4ZqEZy2KCSXv9o7sn51w8N4cdqbfwRDpNDdnyYR5scKD1P74ZAKbGm/*))", descriptor.toString());
    }

    @Test
    public void bip84P2WPKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs");
        Assert.assertEquals("wpkh(xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)", descriptor.toString());
    }

    @Test
    public void redditP2SHP2WPKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("ypub6XiW9nhToS1gjVsFKzgmtWZuqo6V1YY7xaCns37aR3oYhFyAsTehAqV1iW2UCNtgWFQFkz3aNSZZbkfe5d1tD8MzjZuFJQn2XnczsxtjoXr");
        Assert.assertEquals("sh(wpkh(xpub6CtEr82YekUCtCg8Vdu9gRUQfpx34vYd3Tga5eDh33RfeA9wcoV8YmpshJ4tCUEm6cHT1WT1unD1iU45MvbsQtgPsECpiVxYG4ZMVKEKqGP/0/*))", descriptor.toString());
    }

    @Test
    public void masterP2PKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)");
        Assert.assertEquals("pkh(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)", descriptor.toString());
        ExtendedPublicKey extendedPublicKey = descriptor.getSingletonExtendedPublicKey();
        KeyDerivation derivation = descriptor.getKeyDerivation(extendedPublicKey);
        Assert.assertEquals("d34db33f", derivation.getMasterFingerprint());
        Assert.assertEquals("m/44'/0'/0'", derivation.getDerivationPath());
    }
}
