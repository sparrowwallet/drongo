package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Utils;

import java.util.Arrays;
import java.util.List;

/**
 * A linear merkle inclusion proof for a transaction: the sibling path from the txid leaf to the block's merkle root,
 * deepest level first, as returned by the Electrum blockchain.transaction.get_merkle call.
 * Hashes are held in display byte order; hashing is performed in internal byte order.
 */
public class MerkleBranch {
    //A mainnet block's base size caps its transaction count at ~16.7k minimal transactions, so a path deeper than 15 levels is invalid outright
    public static final int MAX_DEPTH = 15;

    private final int position;
    private final List<Sha256Hash> hashes;

    public MerkleBranch(int position, List<Sha256Hash> hashes) {
        this.hashes = List.copyOf(hashes);
        if(position < 0 || this.hashes.size() > MAX_DEPTH || position >= (1 << this.hashes.size())) {
            throw new ProtocolException("Invalid merkle branch position " + position + " for branch of depth " + this.hashes.size());
        }

        this.position = position;
    }

    /**
     * Computes the root this branch reaches from the given leaf, rejecting the two known merkle tree forgeries:
     * an inner node that deserializes as a transaction (CVE-2017-12842), and a duplicated sibling on the left (CVE-2012-2459).
     */
    public Sha256Hash computeRoot(Sha256Hash leaf) throws VerificationException {
        byte[] current = leaf.getReversedBytes();
        for(int i = 0; i < hashes.size(); i++) {
            byte[] sibling = hashes.get(i).getReversedBytes();
            boolean rightChild = ((position >> i) & 1) == 1;
            byte[] innerNode = rightChild ? Utils.concat(sibling, current) : Utils.concat(current, sibling);
            if(isValidTransaction(innerNode)) {
                throw new VerificationException("Merkle branch inner node at level " + i + " is a valid transaction");
            }
            if(rightChild && Arrays.equals(sibling, current)) {
                throw new VerificationException("Merkle branch has a duplicated left sibling at level " + i);
            }
            current = Sha256Hash.hashTwice(innerNode);
        }

        return Sha256Hash.wrapReversed(current);
    }

    public int getDepth() {
        return hashes.size();
    }

    /** Whether the 64 bytes deserialize, strictly and completely, as a transaction with at least one input and one output. */
    static boolean isValidTransaction(byte[] innerNode) {
        try {
            Transaction transaction = new Transaction(innerNode);
            return !transaction.getInputs().isEmpty() && !transaction.getOutputs().isEmpty();
        } catch(Exception e) {
            return false;
        }
    }
}
