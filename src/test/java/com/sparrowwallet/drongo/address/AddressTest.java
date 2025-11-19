package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Network;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

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
    public void bip173InvalidAddressesTest() throws InvalidAddressException {
        List<String> invalidAddresses = Arrays.asList(
                "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", // Invalid human-readable part
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", // Invalid checksum
                "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", // Invalid witness version
                "bc1rw5uspcuh", // Invalid program length
                "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", // Invalid program length
                "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", // Invalid program length for witness version 0 (per BIP141)
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", // Mixed case
                "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", // zero padding of more than 4 bits
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv", // Non-zero padding in 8-to-5 conversion
                "bc1gmk9yu" // Empty data section
        );
        for (String address : invalidAddresses) {
            Assertions.assertThrows(InvalidAddressException.class, () -> Address.fromString(address));
        }
    }

    @Test
    public void bip350InvalidAddressesTest() throws InvalidAddressException {
        List<String> invalidAddresses = Arrays.asList(
                "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut", // Invalid human-readable part
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", // Invalid checksum (Bech32 instead of Bech32m)
                "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf", // Invalid checksum (Bech32 instead of Bech32m)
                "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL", // Invalid checksum (Bech32 instead of Bech32m)
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", // Invalid checksum (Bech32m instead of Bech32)
                "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47", // Invalid checksum (Bech32m instead of Bech32)
                "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4", // Invalid character in checksum
                "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R", // Invalid witness version
                "bc1pw5dgrnzv", // Invalid program length (1 byte)
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav", // Invalid program length (41 bytes)
                "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq", // Mixed case
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf", // zero padding of more than 4 bits
                "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j" // Non-zero padding in 8-to-5 conversion
        );
        for (String address : invalidAddresses) {
            Assertions.assertThrows(InvalidAddressException.class, () -> Address.fromString(address));
        }
    }

    @AfterEach
    public void tearDown() throws Exception {
        Network.set(null);
    }
}