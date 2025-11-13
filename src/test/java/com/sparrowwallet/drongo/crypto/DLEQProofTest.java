package com.sparrowwallet.drongo.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class DLEQProofTest {
    @Test
    public void testDleq() {
        // Use a fixed seed for reproducibility (similar to reference implementation)
        long seed = System.currentTimeMillis();
        Random random = new Random(seed);
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(seed);

        for(int i = 0; i < 10; i++) {
            // Generate random keypairs for both parties
            BigInteger a = generateRandomPrivateKey(random);
            ECKey A = ECKey.fromPrivate(a, true);

            BigInteger b = generateRandomPrivateKey(random);
            ECKey B = ECKey.fromPrivate(b, true);

            // Create shared secret C = a * B
            ECKey C = B.multiply(a, true);

            // Create DLEQ proof
            byte[] randAux = new byte[32];
            random.nextBytes(randAux);
            byte[] proof = DLEQProof.generateProof(a, ECKey.fromPublicOnly(B), randAux, null, null);

            Assertions.assertNotNull(proof, "Proof generation should succeed");

            // Verify DLEQ proof
            boolean success = DLEQProof.verifyProof(A, ECKey.fromPublicOnly(B), C, proof, null, null);
            Assertions.assertTrue(success, "Proof verification should succeed");

            // Flip a random bit in the DLEQ proof and check that verification fails
            for(int j = 0; j < 5; j++) {
                byte[] proofDamaged = proof.clone();
                int byteIndex = random.nextInt(proofDamaged.length);
                int bitIndex = random.nextInt(8);
                proofDamaged[byteIndex] ^= (1 << bitIndex);

                success = DLEQProof.verifyProof(A, ECKey.fromPublicOnly(B), C, proofDamaged, null, null);
                Assertions.assertFalse(success, "Damaged proof verification should fail");
            }

            // Create the same DLEQ proof with a message
            byte[] message = new byte[32];
            random.nextBytes(message);
            proof = DLEQProof.generateProof(a, ECKey.fromPublicOnly(B), randAux, null, message);

            Assertions.assertNotNull(proof, "Proof generation with message should succeed");

            // Verify DLEQ proof with a message
            success = DLEQProof.verifyProof(A, ECKey.fromPublicOnly(B), C, proof, null, message);
            Assertions.assertTrue(success, "Proof verification with message should succeed");

            // Flip a random bit in the DLEQ proof and check that verification fails
            for(int j = 0; j < 5; j++) {
                byte[] proofDamaged = proof.clone();
                int byteIndex = random.nextInt(proofDamaged.length);
                int bitIndex = random.nextInt(8);
                proofDamaged[byteIndex] ^= (1 << bitIndex);

                success = DLEQProof.verifyProof(A, ECKey.fromPublicOnly(B), C, proofDamaged, null, message);
                Assertions.assertFalse(success, "Damaged proof with message verification should fail");
            }
        }
    }

    /**
     * Generate a random private key in the valid range [1, n-1] where n is the curve order.
     */
    private BigInteger generateRandomPrivateKey(Random random) {
        BigInteger n = ECKey.CURVE.getN();
        BigInteger privateKey;

        do {
            // Generate a random BigInteger with the same bit length as n
            privateKey = new BigInteger(n.bitLength(), random);
        } while(privateKey.equals(BigInteger.ZERO) || privateKey.compareTo(n) >= 0);

        return privateKey;
    }
}
