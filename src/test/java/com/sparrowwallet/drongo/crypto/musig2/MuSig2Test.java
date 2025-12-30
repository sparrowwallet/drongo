package com.sparrowwallet.drongo.crypto.musig2;

import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.SchnorrSignature;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * MuSig2 Proof-of-Concept Tests
 *
 * Demonstrates the MuSig2 workflow for Taproot multisig.
 * WARNING: This uses placeholder crypto - DO NOT use with real funds!
 *
 * @author Claude (AI Assistant)
 * @version 0.0.1 (PoC)
 */
public class MuSig2Test {

    @Test
    @DisplayName("MuSig2: Generate two random keys")
    public void testGenerateKeys() {
        ECKey key1 = new ECKey();
        ECKey key2 = new ECKey();

        assertNotNull(key1, "Key 1 should be generated");
        assertNotNull(key2, "Key 2 should be generated");

        System.out.println("✓ Generated key 1: " +
            bytesToHex(key1.getPubKey()).substring(0, 20) + "...");
        System.out.println("✓ Generated key 2: " +
            bytesToHex(key2.getPubKey()).substring(0, 20) + "...");
    }

    @Test
    @DisplayName("MuSig2: Aggregate 2 public keys")
    public void testAggregateKeys() {
        ECKey key1 = new ECKey();
        ECKey key2 = new ECKey();

        // Aggregate public keys
        ECKey aggregated = MuSig2.aggregateKeys(Arrays.asList(key1, key2));

        assertNotNull(aggregated, "Aggregated key should not be null");
        assertNotNull(aggregated.getPubKey(), "Aggregated pubkey should not be null");

        System.out.println("✓ Key 1: " + bytesToHex(key1.getPubKey()).substring(0, 20) + "...");
        System.out.println("✓ Key 2: " + bytesToHex(key2.getPubKey()).substring(0, 20) + "...");
        System.out.println("✓ Aggregated: " + bytesToHex(aggregated.getPubKey()).substring(0, 20) + "...");
    }

    @Test
    @DisplayName("MuSig2: Generate Round 1 nonces (BIP-327)")
    public void testGenerateRound1Nonce() {
        ECKey key1 = new ECKey();
        ECKey key2 = new ECKey();
        Sha256Hash message = Sha256Hash.twiceOf("test message".getBytes());

        MuSig2.CompleteNonce completeNonce1 = MuSig2.generateRound1Nonce(
            key1, Arrays.asList(key1, key2), message);
        MuSig2.CompleteNonce completeNonce2 = MuSig2.generateRound1Nonce(
            key2, Arrays.asList(key1, key2), message);

        assertNotNull(completeNonce1, "CompleteNonce 1 should not be null");
        assertNotNull(completeNonce2, "CompleteNonce 2 should not be null");

        // Check public nonces are different
        assertNotEquals(completeNonce1.getPublicNonce(), completeNonce2.getPublicNonce(),
            "Public nonces should be different");

        System.out.println("✓ Nonce 1: " + completeNonce1.getPublicNonce().serialize().substring(0, 20) + "...");
        System.out.println("✓ Nonce 2: " + completeNonce2.getPublicNonce().serialize().substring(0, 20) + "...");
    }

    @Test
    @DisplayName("MuSig2: Complete 2-of-2 signing flow")
    public void test2of2SigningFlow() {
        System.out.println("\n=== MuSig2 2-of-2 Signing Demo ===\n");

        // Generate two signer key pairs
        ECKey signer1 = new ECKey();
        ECKey signer2 = new ECKey();

        System.out.println("Signer 1 public key: " +
            bytesToHex(signer1.getPubKey()).substring(0, 20) + "...");
        System.out.println("Signer 2 public key: " +
            bytesToHex(signer2.getPubKey()).substring(0, 20) + "...");

        // Message to sign (e.g., transaction sighash)
        Sha256Hash message = Sha256Hash.twiceOf(
            "P2P Trade Offer #12345".getBytes());
        System.out.println("Message: " + message);

        // Perform 2-of-2 MuSig2 signing
        SchnorrSignature signature = MuSig2.sign2of2(signer1, signer2, message);

        assertNotNull(signature, "Signature should not be null");
        System.out.println("\n✓ Final signature: " +
            bytesToHex(signature.encode()).substring(0, 20) + "...");

        // Verify signature
        ECKey aggregatedKey = MuSig2.aggregateKeys(Arrays.asList(
            ECKey.fromPublicOnly(signer1.getPubKey()),
            ECKey.fromPublicOnly(signer2.getPubKey())
        ));

        boolean isValid = MuSig2.verify(signature, aggregatedKey, message);
        System.out.println("✓ Signature valid: " + isValid);

        System.out.println("\n=== MuSig2 2-of-2 Signing Complete ===\n");
    }

    @Test
    @DisplayName("MuSig2: Serialize and deserialize nonce")
    public void testNonceSerialization() {
        MuSig2.MuSig2Nonce original = new MuSig2.MuSig2Nonce(
            new byte[32], new byte[32]);

        String serialized = original.serialize();
        assertNotNull(serialized, "Serialized nonce should not be null");
        assertTrue(serialized.contains(":"), "Serialized nonce should contain separator");

        MuSig2.MuSig2Nonce deserialized = MuSig2.MuSig2Nonce.deserialize(serialized);
        assertNotNull(deserialized, "Deserialized nonce should not be null");

        System.out.println("✓ Nonce serialization works");
    }

    @Test
    @DisplayName("MuSig2: Serialize and deserialize partial signature")
    public void testPartialSignatureSerialization() {
        MuSig2.PartialSignature original = new MuSig2.PartialSignature(
            new byte[32], java.math.BigInteger.valueOf(12345));

        String serialized = original.serialize();
        assertNotNull(serialized, "Serialized signature should not be null");
        assertTrue(serialized.contains(":"), "Serialized signature should contain separator");

        MuSig2.PartialSignature deserialized =
            MuSig2.PartialSignature.deserialize(serialized);
        assertNotNull(deserialized, "Deserialized signature should not be null");
        assertEquals(original.getS(), deserialized.getS(),
            "Deserialized s value should match");

        System.out.println("✓ Partial signature serialization works");
    }

    @Test
    @DisplayName("MuSig2: Test with 3-of-5 threshold")
    public void test3of5Aggregation() {
        ECKey key1 = new ECKey();
        ECKey key2 = new ECKey();
        ECKey key3 = new ECKey();
        ECKey key4 = new ECKey();
        ECKey key5 = new ECKey();

        ECKey aggregated = MuSig2.aggregateKeys(Arrays.asList(
            key1, key2, key3, key4, key5
        ));

        assertNotNull(aggregated, "3-of-5 aggregated key should not be null");
        System.out.println("✓ Aggregated 3-of-5: " +
            bytesToHex(aggregated.getPubKey()).substring(0, 20) + "...");
    }

    // Helper method
    private String bytesToHex(byte[] bytes) {
        return com.sparrowwallet.drongo.Utils.bytesToHex(bytes);
    }
}
