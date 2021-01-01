package com.sparrowwallet.drongo;

import org.junit.Assert;
import org.junit.Test;

import java.util.Iterator;
import java.util.Set;

public class OutputDescriptorTest {

    @Test
    public void electrumP2PKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("xpub661MyMwAqRbcFT5HwyRoP5hebbeRDvy2RGDTH2uxFyDPaf5FLtu4njuishddViQxTABZKzoWKuwpy6MsgfPvTw9pKnRGDL5eBxDej9kF54Z");
        Assert.assertEquals("pkh(xpub661MyMwAqRbcFT5HwyRoP5hebbeRDvy2RGDTH2uxFyDPaf5FLtu4njuishddViQxTABZKzoWKuwpy6MsgfPvTw9pKnRGDL5eBxDej9kF54Z)", descriptor.toString());
    }

    @Test
    public void iancolemanP2PKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("xpub6EEznxrqoN5HUXfD3QC3B8Vjw8Lj9UnRj17uTzNaBnEYN5xgwe6Un46Z443sSTBP2bzLZuDzygkdD1FtVWSexFmg4yAuCTxE2HxXFtz541z/*");
        Assert.assertEquals("pkh(xpub6EEznxrqoN5HUXfD3QC3B8Vjw8Lj9UnRj17uTzNaBnEYN5xgwe6Un46Z443sSTBP2bzLZuDzygkdD1FtVWSexFmg4yAuCTxE2HxXFtz541z/*)", descriptor.toString());
    }

    @Test
    public void electrumP2WPKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("zpub6njbcfTHEfK4U96Z8dBaTULdb1LGWMtj73yYZ76kfmE9nuf3KhNSsXfzDefz5KV6TreWjnQbgvnSmSttudzTugesV2HFunYu7gWYJUD4eoR");
        Assert.assertEquals("wpkh(xpub69551L7SwJE6mYiKTucL3J9dF53Nd7ujGpw6zKJyukUPgi2apP3KdQMiBEkp5WBFeaQuEqDUmc5LzsfmUFASKDHfkLtQjxuvaEPFXNDF4Kg)", descriptor.toString());
    }

    @Test
    public void iancolemanP2SHP2WPKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("ypub6Zken22QbjfomRUXki5v4ndP6T1DEtaBhGGZBvR4ocoooM44dFmnF8DyFmvcK76TKnuvdFfaPnicVvTAPdqEcbuEfKEqfnRoUjSkTB4u1os/*");
        Assert.assertEquals("sh(wpkh(xpub6EvPUMMVT48Kv8HQvMJHrhXsvUrmJGagn9kLQXXBRcRvkFEqNbcDd4ZqEZy2KCSXv9o7sn51w8N4cdqbfwRDpNDdnyYR5scKD1P74ZAKbGm/*))", descriptor.toString());
    }

    @Test
    public void bip84P2WPKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs");
        Assert.assertEquals("wpkh(xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V)", descriptor.toString());
    }

    @Test
    public void redditP2SHP2WPKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("ypub6XiW9nhToS1gjVsFKzgmtWZuqo6V1YY7xaCns37aR3oYhFyAsTehAqV1iW2UCNtgWFQFkz3aNSZZbkfe5d1tD8MzjZuFJQn2XnczsxtjoXr");
        Assert.assertEquals("sh(wpkh(xpub6CtEr82YekUCtCg8Vdu9gRUQfpx34vYd3Tga5eDh33RfeA9wcoV8YmpshJ4tCUEm6cHT1WT1unD1iU45MvbsQtgPsECpiVxYG4ZMVKEKqGP))", descriptor.toString());
    }

    @Test
    public void masterP2PKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)");
        Assert.assertEquals("pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)", descriptor.toString());
        ExtendedKey extendedPublicKey = descriptor.getSingletonExtendedPublicKey();
        KeyDerivation derivation = descriptor.getKeyDerivation(extendedPublicKey);
        Assert.assertEquals("d34db33f", derivation.getMasterFingerprint());
        Assert.assertEquals("m/44'/0'/0'", derivation.getDerivationPath());
        Assert.assertEquals("14qCH92HCyDDBFFZdhDt1WMfrMDYnBFYMF", descriptor.getAddress(descriptor.getChangeDerivation(0)).toString());
    }

    @Test
    public void singleP2SH_P2WPKH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("sh(wpkh([f09a3b29/49h/0h/0h]xpub6CjUWYtkq9KT1zkM5NPMxoJTCMm8JSFw7JPyMG6YLBzv5AsCTkASnsVyJhqL1aaqF5XSsFinHK3FDi8RoeEWcTG3DQA2TjqrZ6HJtatYbsU/0/*))");
        Assert.assertEquals("sh(wpkh([f09a3b29/49'/0'/0']xpub6CjUWYtkq9KT1zkM5NPMxoJTCMm8JSFw7JPyMG6YLBzv5AsCTkASnsVyJhqL1aaqF5XSsFinHK3FDi8RoeEWcTG3DQA2TjqrZ6HJtatYbsU/0/*))", descriptor.toString());
        ExtendedKey extendedPublicKey = descriptor.getSingletonExtendedPublicKey();
        KeyDerivation derivation = descriptor.getKeyDerivation(extendedPublicKey);
        Assert.assertEquals("f09a3b29", derivation.getMasterFingerprint());
        Assert.assertEquals("m/49'/0'/0'", derivation.getDerivationPath());
        Assert.assertEquals("31sNBFoYAaFggvNBAnnnLAc5ygfjZRCK6s", descriptor.getAddress(descriptor.getChangeDerivation(0)).toString());
    }

    @Test
    public void multisigP2WSH() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("wsh(sortedmulti(2,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/*))");
        Assert.assertEquals("wsh(sortedmulti(2,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/*))", descriptor.toString());
        Assert.assertEquals(2, descriptor.getMultisigThreshold());
        Assert.assertEquals("bc1qf5l7g5t5v2tp2wnwfeqlktkds7zvprmm7afjn6f85fdesc2pwedsh42kcl", descriptor.getAddress(KeyDerivation.parsePath("0/0")).toString());
    }

    @Test
    public void multisigP2WSH2() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("wsh(sortedmulti(2,[04fefef0/48h/0h/0h/2h]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0/*,[04ba1ef0/48h/0h/0h/2h]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/*))");
        Set<ExtendedKey> extendedPublicKeys = descriptor.getExtendedPublicKeys();
        Iterator<ExtendedKey> iter = extendedPublicKeys.iterator();
        ExtendedKey extendedPublicKey1 = iter.next();
        Assert.assertEquals("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB", extendedPublicKey1.toString());
        KeyDerivation derivation = descriptor.getKeyDerivation(extendedPublicKey1);
        Assert.assertEquals("04fefef0", derivation.getMasterFingerprint());
        Assert.assertEquals("m/48'/0'/0'/2'", derivation.getDerivationPath());

        ExtendedKey extendedPublicKey2 = iter.next();
        Assert.assertEquals("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH", extendedPublicKey2.toString());
        KeyDerivation derivation2 = descriptor.getKeyDerivation(extendedPublicKey2);
        Assert.assertEquals("04ba1ef0", derivation2.getMasterFingerprint());
        Assert.assertEquals("m/48'/0'/0'/2'", derivation2.getDerivationPath());
    }

    @Test
    public void testChecksum() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t");
        Assert.assertEquals("sh(sortedmulti(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#s66h0xn6", descriptor.toString(true));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPubKeySingle() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPubKeyMulti() {
        OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor("sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))");
    }
}
