package com.sparrowwallet.drongo.address;

import org.junit.Assert;
import org.junit.Test;

import java.security.SecureRandom;

public class AddressTest {
    @Test
    public void validAddressTest() throws InvalidAddressException {
        Address address1 = Address.fromString("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        Assert.assertTrue(address1 instanceof P2WPKHAddress);
        Assert.assertEquals("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", address1.toString());

        Address address2 = Address.fromString("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3");
        Assert.assertTrue(address2 instanceof P2WSHAddress);
        Assert.assertEquals("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", address2.toString());

        Address address3 = Address.fromString("19Sp9dLinHy3dKo2Xxj53ouuZWAoVGGhg8");
        Assert.assertTrue(address3 instanceof P2PKHAddress);
        Assert.assertEquals("19Sp9dLinHy3dKo2Xxj53ouuZWAoVGGhg8", address3.toString());

        Address address4 = Address.fromString("34jnjFM4SbaB7Q8aMtNDG849RQ1gUYgpgo");
        Assert.assertTrue(address4 instanceof P2SHAddress);
        Assert.assertEquals("34jnjFM4SbaB7Q8aMtNDG849RQ1gUYgpgo", address4.toString());
    }

    @Test
    public void validRandomAddressTest() throws InvalidAddressException {
        SecureRandom random = new SecureRandom();
        byte[] values = new byte[20];

        for(int i = 0; i < 100; i++) {
            random.nextBytes(values);
            Address address = (i % 2 == 0 ? new P2PKHAddress(values) : new P2WPKHAddress(values));
            String strAddress = address.toString();
            Address checkAddress = Address.fromString(strAddress);
            Assert.assertArrayEquals(values, checkAddress.getHash());
        }

        byte[] values32 = new byte[32];
        for(int i = 0; i < 100; i++) {
            random.nextBytes(values32);
            Address address = new P2WSHAddress(values32);
            String strAddress = address.toString();
            Address checkAddress = Address.fromString(strAddress);
            Assert.assertArrayEquals(values32, checkAddress.getHash());
        }
    }

    @Test(expected = InvalidAddressException.class)
    public void invalidCharacterAddressTest() throws InvalidAddressException {
        Address address1 = Address.fromString("bc1qw508d6qejxtdg4y5R3zarvary0c5xw7kv8f3t4");
    }

    @Test(expected = InvalidAddressException.class)
    public void invalidVersionAddressTest() throws InvalidAddressException {
        Address address1 = Address.fromString("44jnjFM4SbaB7Q8aMtNDG849RQ1gUYgpgo");
    }

    @Test(expected = InvalidAddressException.class)
    public void invalidChecksumAddressTest() throws InvalidAddressException {
        Address address1 = Address.fromString("34jnjFM4SbaB7Q7aMtNDG849RQ1gUYgpgo");
    }

    @Test(expected = InvalidAddressException.class)
    public void invalidChecksumAddressTest2() throws InvalidAddressException {
        Address address1 = Address.fromString("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmb3");
    }
}