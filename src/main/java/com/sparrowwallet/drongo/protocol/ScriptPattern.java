package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.address.P2PKAddress;
import com.sparrowwallet.drongo.crypto.ECKey;

import java.util.ArrayList;
import java.util.List;

import static com.sparrowwallet.drongo.protocol.ScriptOpCodes.*;
import static com.sparrowwallet.drongo.protocol.Script.decodeFromOpN;

public class ScriptPattern {
    /**
     * Returns true if this script is of the form {@code DUP HASH160 <pubkey hash> EQUALVERIFY CHECKSIG}, ie, payment to an
     * public key like {@code 2102f3b08938a7f8d2609d567aebc4989eeded6e2e880c058fdf092c5da82c3bc5eeac}.
     */
    public static boolean isP2PK(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        if (chunks.size() != 2)
            return false;
        if (!chunks.get(0).equalsOpCode(0x21) && !chunks.get(0).equalsOpCode(0x41))
            return false;
        byte[] chunk2data = chunks.get(0).data;
        if (chunk2data == null)
            return false;
        if (chunk2data.length != 33 && chunk2data.length != 65)
            return false;
        if (!chunks.get(1).equalsOpCode(OP_CHECKSIG))
            return false;
        return true;
    }

    /**
     * Extract the pubkey from a P2PK scriptPubKey. It's important that the script is in the correct form, so you
     * will want to guard calls to this method with {@link #isP2PK(Script)}.
     */
    public static ECKey extractPKFromP2PK(Script script) {
        return ECKey.fromPublicOnly(script.chunks.get(0).data);
    }

    /**
     * Returns true if this script is of the form {@code DUP HASH160 <pubkey hash> EQUALVERIFY CHECKSIG}, ie, payment to an
     * address like {@code 1VayNert3x1KzbpzMGt2qdqrAThiRovi8}. This form was originally intended for the case where you wish
     * to send somebody money with a written code because their node is offline, but over time has become the standard
     * way to make payments due to the short and recognizable base58 form addresses come in.
     */
    public static boolean isP2PKH(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        if (chunks.size() != 5)
            return false;
        if (!chunks.get(0).equalsOpCode(OP_DUP))
            return false;
        if (!chunks.get(1).equalsOpCode(OP_HASH160))
            return false;
        byte[] chunk2data = chunks.get(2).data;
        if (chunk2data == null)
            return false;
        if (chunk2data.length != 20)
            return false;
        if (!chunks.get(3).equalsOpCode(OP_EQUALVERIFY))
            return false;
        if (!chunks.get(4).equalsOpCode(OP_CHECKSIG))
            return false;
        return true;
    }

    /**
     * Extract the pubkey hash from a P2PKH scriptPubKey. It's important that the script is in the correct form, so you
     * will want to guard calls to this method with {@link #isP2PKH(Script)}.
     */
    public static byte[] extractHashFromP2PKH(Script script) {
        return script.chunks.get(2).data;
    }

    /**
     * <p>
     * Whether or not this is a scriptPubKey representing a P2SH output. In such outputs, the logic that
     * controls reclamation is not actually in the output at all. Instead there's just a hash, and it's up to the
     * spending input to provide a program matching that hash.
     * </p>
     * <p>
     * P2SH is described by <a href="https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki">BIP16</a>.
     * </p>
     */
    public static boolean isP2SH(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        // We check for the effective serialized form because BIP16 defines a P2SH output using an exact byte
        // template, not the logical program structure. Thus you can have two programs that look identical when
        // printed out but one is a P2SH script and the other isn't! :(
        // We explicitly test that the op code used to load the 20 bytes is 0x14 and not something logically
        // equivalent like {@code OP_HASH160 OP_PUSHDATA1 0x14 <20 bytes of script hash> OP_EQUAL}
        if (chunks.size() != 3)
            return false;
        if (!chunks.get(0).equalsOpCode(OP_HASH160))
            return false;
        ScriptChunk chunk1 = chunks.get(1);
        if (chunk1.opcode != 0x14)
            return false;
        byte[] chunk1data = chunk1.data;
        if (chunk1data == null)
            return false;
        if (chunk1data.length != 20)
            return false;
        if (!chunks.get(2).equalsOpCode(OP_EQUAL))
            return false;
        return true;
    }

    /**
     * Extract the script hash from a P2SH scriptPubKey. It's important that the script is in the correct form, so you
     * will want to guard calls to this method with {@link #isP2SH(Script)}.
     */
    public static byte[] extractHashFromP2SH(Script script) {
        return script.chunks.get(1).data;
    }

    /**
     * Returns whether this script matches the format used for multisig outputs:
     * {@code [n] [keys...] [m] CHECKMULTISIG}
     */
    public static boolean isMultisig(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        if (chunks.size() < 4) return false;
        ScriptChunk chunk = chunks.get(chunks.size() - 1);
        // Must end in OP_CHECKMULTISIG[VERIFY].
        if (!chunk.isOpCode()) return false;
        if (!(chunk.equalsOpCode(OP_CHECKMULTISIG) || chunk.equalsOpCode(OP_CHECKMULTISIGVERIFY))) return false;
        try {
            // Second to last chunk must be an OP_N opcode and there should be that many data chunks (keys).
            ScriptChunk m = chunks.get(chunks.size() - 2);
            if (!m.isOpCode()) return false;
            int numKeys = decodeFromOpN(m.opcode);
            if (numKeys < 1 || chunks.size() != 3 + numKeys) return false;
            for (int i = 1; i < chunks.size() - 2; i++) {
                if (chunks.get(i).isOpCode()) return false;
            }
            // First chunk must be an OP_N opcode too.
            if (decodeFromOpN(chunks.get(0).opcode) < 1) return false;
        } catch (IllegalStateException e) {
            return false;   // Not an OP_N opcode.
        }
        return true;
    }

    public static int extractMultisigThreshold(Script script) {
        return decodeFromOpN(script.chunks.get(0).opcode);
    }

    public static Address[] extractMultisigAddresses(Script script) {
        List<Address> addresses = new ArrayList<>();

        List<ScriptChunk> chunks = script.chunks;
        for (int i = 1; i < chunks.size() - 2; i++) {
            byte[] pubKey = chunks.get(i).data;
            addresses.add(new P2PKAddress(pubKey));
        }

        return addresses.toArray(new Address[addresses.size()]);
    }

    /**
     * Returns true if this script is of the form {@code OP_0 <hash[20]>}. This is a P2WPKH scriptPubKey.
     */
    public static boolean isP2WPKH(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        if (chunks.size() != 2)
            return false;
        if (!chunks.get(0).equalsOpCode(OP_0))
            return false;
        byte[] chunk1data = chunks.get(1).data;
        if (chunk1data == null)
            return false;
        if (chunk1data.length != 20)
            return false;
        return true;
    }

    /**
     * Returns true if this script is of the form {@code OP_0 <hash[32]>}. This is a P2WSH scriptPubKey.
     */
    public static boolean isP2WSH(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        if (chunks.size() != 2)
            return false;
        if (!chunks.get(0).equalsOpCode(OP_0))
            return false;
        byte[] chunk1data = chunks.get(1).data;
        if (chunk1data == null)
            return false;
        if (chunk1data.length != 32)
            return false;
        return true;
    }

    /**
     * Extract the pubkey hash from a P2WPKH or the script hash from a P2WSH scriptPubKey. It's important that the
     * script is in the correct form, so you will want to guard calls to this method with
     * {@link #isP2WPKH(Script)} or {@link #isP2WSH(Script)}.
     */
    public static byte[] extractHashFromP2WH(Script script) {
        return script.chunks.get(1).data;
    }
}
