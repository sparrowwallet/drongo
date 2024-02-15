package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Network;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

public class AddressTest {
    @Test
    public void validAddressTest() throws InvalidAddressException {
        Address address1 = Address.fromString("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        Assertions.assertTrue(address1 instanceof P2WPKHAddress);
        Assertions.assertEquals("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", address1.toString());

        Address address2 = Address.fromString("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3");
        Assertions.assertTrue(address2 instanceof P2WSHAddress);
        Assertions.assertEquals("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", address2.toString());

        Address address3 = Address.fromString("19Sp9dLinHy3dKo2Xxj53ouuZWAoVGGhg8");
        Assertions.assertTrue(address3 instanceof P2PKHAddress);
        Assertions.assertEquals("19Sp9dLinHy3dKo2Xxj53ouuZWAoVGGhg8", address3.toString());

        Address address4 = Address.fromString("34jnjFM4SbaB7Q8aMtNDG849RQ1gUYgpgo");
        Assertions.assertTrue(address4 instanceof P2SHAddress);
        Assertions.assertEquals("34jnjFM4SbaB7Q8aMtNDG849RQ1gUYgpgo", address4.toString());

        Address address5 = Address.fromString(Network.TESTNET, "tb1qawkzyj2l5yck5jq4wyhkc4837x088580y9uyk8");
        Assertions.assertTrue(address5 instanceof P2WPKHAddress);
        Assertions.assertEquals("tb1qawkzyj2l5yck5jq4wyhkc4837x088580y9uyk8", address5.toString(Network.TESTNET));

        Address address6 = Address.fromString(Network.TESTNET, "tb1q8kdkthp5a6vfrdas84efkpv25ul3s9wpzc755cra8av48xq4a7wsjcsdma");
        Assertions.assertTrue(address6 instanceof P2WSHAddress);
        Assertions.assertEquals("tb1q8kdkthp5a6vfrdas84efkpv25ul3s9wpzc755cra8av48xq4a7wsjcsdma", address6.toString(Network.TESTNET));

        Address address7 = Address.fromString(Network.TESTNET, "mng6R5oLWBBo8iFWU9Mx4zFy5pWhrWMeW2");
        Assertions.assertTrue(address7 instanceof P2PKHAddress);
        Assertions.assertEquals("mng6R5oLWBBo8iFWU9Mx4zFy5pWhrWMeW2", address7.toString(Network.TESTNET));

        Address address8 = Address.fromString(Network.TESTNET, "n1S1rnnZm3RdW9iuAF6Hjk3gLZWGc59zDi");
        Assertions.assertTrue(address8 instanceof P2PKHAddress);
        Assertions.assertEquals("n1S1rnnZm3RdW9iuAF6Hjk3gLZWGc59zDi", address8.toString(Network.TESTNET));

        Address address9 = Address.fromString(Network.TESTNET, "2NCZUtUt6gzXyBiPEQi5yQyrgR6f6F6Ki6A");
        Assertions.assertTrue(address9 instanceof P2SHAddress);
        Assertions.assertEquals("2NCZUtUt6gzXyBiPEQi5yQyrgR6f6F6Ki6A", address9.toString(Network.TESTNET));

        Address address10 = Address.fromString(Network.SIGNET, "2NCZUtUt6gzXyBiPEQi5yQyrgR6f6F6Ki6A");
        Assertions.assertTrue(address10 instanceof P2SHAddress);
        Assertions.assertEquals("2NCZUtUt6gzXyBiPEQi5yQyrgR6f6F6Ki6A", address10.toString(Network.SIGNET));

        Address address11 = Address.fromString("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0");
        Assertions.assertTrue(address11 instanceof P2TRAddress);
        Assertions.assertEquals("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", address11.toString());

        Address address12 = Address.fromString(Network.TESTNET, "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c");
        Assertions.assertTrue(address12 instanceof P2TRAddress);
        Assertions.assertEquals("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", address12.toString(Network.TESTNET));
    }

    @Test
    public void testnetValidAddressTest() throws InvalidAddressException {
        Network.set(Network.TESTNET);

        Address address5 = Address.fromString("tb1qawkzyj2l5yck5jq4wyhkc4837x088580y9uyk8");
        Assertions.assertTrue(address5 instanceof P2WPKHAddress);
        Assertions.assertEquals("tb1qawkzyj2l5yck5jq4wyhkc4837x088580y9uyk8", address5.toString());

        Address address6 = Address.fromString("tb1q8kdkthp5a6vfrdas84efkpv25ul3s9wpzc755cra8av48xq4a7wsjcsdma");
        Assertions.assertTrue(address6 instanceof P2WSHAddress);
        Assertions.assertEquals("tb1q8kdkthp5a6vfrdas84efkpv25ul3s9wpzc755cra8av48xq4a7wsjcsdma", address6.toString());

        Address address7 = Address.fromString("mng6R5oLWBBo8iFWU9Mx4zFy5pWhrWMeW2");
        Assertions.assertTrue(address7 instanceof P2PKHAddress);
        Assertions.assertEquals("mng6R5oLWBBo8iFWU9Mx4zFy5pWhrWMeW2", address7.toString());

        Address address8 = Address.fromString("n1S1rnnZm3RdW9iuAF6Hjk3gLZWGc59zDi");
        Assertions.assertTrue(address8 instanceof P2PKHAddress);
        Assertions.assertEquals("n1S1rnnZm3RdW9iuAF6Hjk3gLZWGc59zDi", address8.toString());

        Address address9 = Address.fromString("2NCZUtUt6gzXyBiPEQi5yQyrgR6f6F6Ki6A");
        Assertions.assertTrue(address9 instanceof P2SHAddress);
        Assertions.assertEquals("2NCZUtUt6gzXyBiPEQi5yQyrgR6f6F6Ki6A", address9.toString());

        Address address12 = Address.fromString("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c");
        Assertions.assertTrue(address12 instanceof P2TRAddress);
        Assertions.assertEquals("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", address12.toString());
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
            Assertions.assertArrayEquals(values, checkAddress.getData());
        }

        byte[] values32 = new byte[32];
        for(int i = 0; i < 100; i++) {
            random.nextBytes(values32);
            Address address = new P2WSHAddress(values32);
            String strAddress = address.toString();
            Address checkAddress = Address.fromString(strAddress);
            Assertions.assertArrayEquals(values32, checkAddress.getData());
        }
    }

    @Test
    public void invalidCharacterAddressTest() throws InvalidAddressException {
        Assertions.assertThrows(InvalidAddressException.class, () -> Address.fromString("bc1qw508d6qejxtdg4y5R3zarvary0c5xw7kv8f3t4"));
    }

    @Test
    public void invalidVersionAddressTest() throws InvalidAddressException {
        Assertions.assertThrows(InvalidAddressException.class, () -> Address.fromString("44jnjFM4SbaB7Q8aMtNDG849RQ1gUYgpgo"));
    }

    @Test
    public void invalidChecksumAddressTest() throws InvalidAddressException {
        Assertions.assertThrows(InvalidAddressException.class, () -> Address.fromString("34jnjFM4SbaB7Q7aMtNDG849RQ1gUYgpgo"));
    }

    @Test
    public void invalidChecksumAddressTest2() throws InvalidAddressException {
        Assertions.assertThrows(InvalidAddressException.class, () -> Address.fromString("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmb3"));
    }

    @Test
    public void invalidEncodingAddressTest() throws InvalidAddressException {
        Assertions.assertThrows(InvalidAddressException.class, () -> Address.fromString("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh"));
    }

    @AfterEach
    public void tearDown() throws Exception {
        Network.set(null);
    }
}