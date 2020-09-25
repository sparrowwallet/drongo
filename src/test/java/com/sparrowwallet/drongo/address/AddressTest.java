package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.Network;

import org.junit.Assert;
import org.junit.Test;

import java.security.SecureRandom;

public class AddressTest {
    @Test
    public void validAddressTest() throws InvalidAddressException {
        Address address1 = Address.fromString(Network.BITCOIN, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        Assert.assertTrue(address1 instanceof P2WPKHAddress);
        Assert.assertEquals("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", address1.toString());

        Address address2 = Address.fromString(Network.BITCOIN, "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3");
        Assert.assertTrue(address2 instanceof P2WSHAddress);
        Assert.assertEquals("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", address2.toString());

        Address address3 = Address.fromString(Network.BITCOIN, "19Sp9dLinHy3dKo2Xxj53ouuZWAoVGGhg8");
        Assert.assertTrue(address3 instanceof P2PKHAddress);
        Assert.assertEquals("19Sp9dLinHy3dKo2Xxj53ouuZWAoVGGhg8", address3.toString());

        Address address4 = Address.fromString(Network.BITCOIN, "34jnjFM4SbaB7Q8aMtNDG849RQ1gUYgpgo");
        Assert.assertTrue(address4 instanceof P2SHAddress);
        Assert.assertEquals("34jnjFM4SbaB7Q8aMtNDG849RQ1gUYgpgo", address4.toString());

        Address address5 = Address.fromString(Network.TESTNET, "tb1qawkzyj2l5yck5jq4wyhkc4837x088580y9uyk8");
        Assert.assertTrue(address5 instanceof P2WPKHAddress);
        Assert.assertEquals("tb1qawkzyj2l5yck5jq4wyhkc4837x088580y9uyk8", address5.toString());

        Address address6 = Address.fromString(Network.TESTNET, "tb1q8kdkthp5a6vfrdas84efkpv25ul3s9wpzc755cra8av48xq4a7wsjcsdma");
        Assert.assertTrue(address6 instanceof P2WSHAddress);
        Assert.assertEquals("tb1q8kdkthp5a6vfrdas84efkpv25ul3s9wpzc755cra8av48xq4a7wsjcsdma", address6.toString());

        Address address7 = Address.fromString(Network.TESTNET, "mng6R5oLWBBo8iFWU9Mx4zFy5pWhrWMeW2");
        Assert.assertTrue(address7 instanceof P2PKHAddress);
        Assert.assertEquals("mng6R5oLWBBo8iFWU9Mx4zFy5pWhrWMeW2", address7.toString());

        Address address8 = Address.fromString(Network.TESTNET, "n1S1rnnZm3RdW9iuAF6Hjk3gLZWGc59zDi");
        Assert.assertTrue(address8 instanceof P2PKHAddress);
        Assert.assertEquals("n1S1rnnZm3RdW9iuAF6Hjk3gLZWGc59zDi", address8.toString());

        Address address9 = Address.fromString(Network.TESTNET, "2NCZUtUt6gzXyBiPEQi5yQyrgR6f6F6Ki6A");
        Assert.assertTrue(address9 instanceof P2SHAddress);
        Assert.assertEquals("2NCZUtUt6gzXyBiPEQi5yQyrgR6f6F6Ki6A", address9.toString());
    }

    @Test
    public void validRandomAddressTest() throws InvalidAddressException {
        SecureRandom random = new SecureRandom();
        byte[] values = new byte[20];

        for(int i = 0; i < 100; i++) {
            random.nextBytes(values);
            Address address = (i % 2 == 0 ? new P2PKHAddress(Network.BITCOIN, values) : new P2WPKHAddress(Network.BITCOIN, values));
            String strAddress = address.toString();
            Address checkAddress = Address.fromString(Network.BITCOIN, strAddress);
            Assert.assertArrayEquals(values, checkAddress.getHash());
        }

        byte[] values32 = new byte[32];
        for(int i = 0; i < 100; i++) {
            random.nextBytes(values32);
            Address address = new P2WSHAddress(Network.BITCOIN, values32);
            String strAddress = address.toString();
            Address checkAddress = Address.fromString(Network.BITCOIN, strAddress);
            Assert.assertArrayEquals(values32, checkAddress.getHash());
        }
    }

    @Test(expected = InvalidAddressException.class)
    public void invalidCharacterAddressTest() throws InvalidAddressException {
        Address address1 = Address.fromString(Network.BITCOIN, "bc1qw508d6qejxtdg4y5R3zarvary0c5xw7kv8f3t4");
    }

    @Test(expected = InvalidAddressException.class)
    public void invalidVersionAddressTest() throws InvalidAddressException {
        Address address1 = Address.fromString(Network.BITCOIN, "44jnjFM4SbaB7Q8aMtNDG849RQ1gUYgpgo");
    }

    @Test(expected = InvalidAddressException.class)
    public void invalidChecksumAddressTest() throws InvalidAddressException {
        Address address1 = Address.fromString(Network.BITCOIN, "34jnjFM4SbaB7Q7aMtNDG849RQ1gUYgpgo");
    }

    @Test(expected = InvalidAddressException.class)
    public void invalidChecksumAddressTest2() throws InvalidAddressException {
        Address address1 = Address.fromString(Network.BITCOIN, "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmb3");
    }
}