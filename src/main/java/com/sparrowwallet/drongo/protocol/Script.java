package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.sparrowwallet.drongo.protocol.ScriptOpCodes.*;

public class Script {
    public static final long MAX_SCRIPT_ELEMENT_SIZE = 520;

    // The program is a set of chunks where each element is either [opcode] or [data, data, data ...]
    protected List<ScriptChunk> chunks;

    protected byte[] program;

    public Script(byte[] programBytes) {
        program = programBytes;
        parse(programBytes);
    }

    public Script(List<ScriptChunk> chunks) {
        this.chunks = Collections.unmodifiableList(new ArrayList<>(chunks));
    }

    private static final ScriptChunk[] STANDARD_TRANSACTION_SCRIPT_CHUNKS = {
            new ScriptChunk(ScriptOpCodes.OP_DUP, null, 0),
            new ScriptChunk(ScriptOpCodes.OP_HASH160, null, 1),
            new ScriptChunk(ScriptOpCodes.OP_EQUALVERIFY, null, 23),
            new ScriptChunk(ScriptOpCodes.OP_CHECKSIG, null, 24),
    };

    private void parse(byte[] program) {
        chunks = new ArrayList<>(5);   // Common size.
        ByteArrayInputStream bis = new ByteArrayInputStream(program);
        int initialSize = bis.available();
        while (bis.available() > 0) {
            int startLocationInProgram = initialSize - bis.available();
            int opcode = bis.read();

            long dataToRead = -1;
            if (opcode >= 0 && opcode < OP_PUSHDATA1) {
                // Read some bytes of data, where how many is the opcode value itself.
                dataToRead = opcode;
            } else if (opcode == OP_PUSHDATA1) {
                if (bis.available() < 1) throw new ProtocolException("Unexpected end of script");
                dataToRead = bis.read();
            } else if (opcode == OP_PUSHDATA2) {
                // Read a short, then read that many bytes of data.
                if (bis.available() < 2) throw new ProtocolException("Unexpected end of script");
                dataToRead = Utils.readUint16FromStream(bis);
            } else if (opcode == OP_PUSHDATA4) {
                // Read a uint32, then read that many bytes of data.
                // Though this is allowed, because its value cannot be > 520, it should never actually be used
                if (bis.available() < 4) throw new ProtocolException("Unexpected end of script");
                dataToRead = Utils.readUint32FromStream(bis);
            }

            ScriptChunk chunk;
            if (dataToRead == -1) {
                chunk = new ScriptChunk(opcode, null, startLocationInProgram);
            } else {
                if (dataToRead > bis.available())
                    throw new ProtocolException("Push of data element that is larger than remaining data");
                byte[] data = new byte[(int)dataToRead];
                if(dataToRead != 0 && bis.read(data, 0, (int)dataToRead) != dataToRead) {
                    throw new ProtocolException();
                }

                chunk = new ScriptChunk(opcode, data, startLocationInProgram);
            }
            // Save some memory by eliminating redundant copies of the same chunk objects.
            for (ScriptChunk c : STANDARD_TRANSACTION_SCRIPT_CHUNKS) {
                if (c.equals(chunk)) chunk = c;
            }
            chunks.add(chunk);
        }
    }

    /** Returns the serialized program as a newly created byte array. */
    public byte[] getProgram() {
        try {
            // Don't round-trip as Bitcoin Core doesn't and it would introduce a mismatch.
            if (program != null)
                return Arrays.copyOf(program, program.length);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            for (ScriptChunk chunk : chunks) {
                chunk.write(bos);
            }
            program = bos.toByteArray();
            return program;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    public String getProgramAsHex() {
        return Hex.toHexString(getProgram());
    }

    public List<ScriptChunk> getChunks() {
        return Collections.unmodifiableList(chunks);
    }

    /**
     * Returns true if this script has the required form to contain a destination address
     */
    public boolean containsToAddress() {
        return ScriptPattern.isP2PK(this) || ScriptPattern.isP2PKH(this) || ScriptPattern.isP2SH(this) || ScriptPattern.isP2WPKH(this) || ScriptPattern.isP2WSH(this) || ScriptPattern.isMultisig(this);
    }

    /**
     * <p>If the program somehow pays to a hash, returns the hash.</p>
     *
     * <p>Otherwise this method throws a ScriptException.</p>
     */
    public byte[] getPubKeyHash() throws ProtocolException {
        if (ScriptPattern.isP2PKH(this))
            return ScriptPattern.extractHashFromP2PKH(this);
        else if (ScriptPattern.isP2SH(this))
            return ScriptPattern.extractHashFromP2SH(this);
        else if (ScriptPattern.isP2WPKH(this) || ScriptPattern.isP2WSH(this))
            return ScriptPattern.extractHashFromP2WH(this);
        else
            throw new ProtocolException("Script not in the standard scriptPubKey form");
    }

    /**
     * Gets the destination address from this script, if it's in the required form.
     */
    public Address[] getToAddresses() throws NonStandardScriptException {
        if (ScriptPattern.isP2PK(this))
            return new Address[] { new P2PKAddress( ScriptPattern.extractPKFromP2PK(this)) };
        else if (ScriptPattern.isP2PKH(this))
            return new Address[] { new P2PKHAddress( ScriptPattern.extractHashFromP2PKH(this)) };
        else if (ScriptPattern.isP2SH(this))
            return new Address[] { new P2SHAddress(ScriptPattern.extractHashFromP2SH(this)) };
        else if (ScriptPattern.isP2WPKH(this))
            return new Address[] { new P2WPKHAddress(ScriptPattern.extractHashFromP2WH(this)) };
        else if (ScriptPattern.isP2WSH(this))
            return new Address[] { new P2WSHAddress(ScriptPattern.extractHashFromP2WH(this)) };
        else if (ScriptPattern.isMultisig(this))
            return ScriptPattern.extractMultisigAddresses(this);
        else
            throw new NonStandardScriptException("Cannot find addresses in non standard script: " + toString());
    }

    public int getNumRequiredSignatures() throws NonStandardScriptException {
        if(ScriptPattern.isP2PK(this) || ScriptPattern.isP2PKH(this) || ScriptPattern.isP2WPKH(this)) {
            return 1;
        }

        if(ScriptPattern.isMultisig(this)) {
            return ScriptPattern.extractMultisigThreshold(this);
        }

        throw new NonStandardScriptException("Cannot find number of required signatures for non standard script: " + toString());
    }

    public static int decodeFromOpN(int opcode) {
        if((opcode != OP_0 && opcode != OP_1NEGATE) && (opcode < OP_1 || opcode > OP_16)) {
            throw new ProtocolException("decodeFromOpN called on non OP_N opcode: " + opcode);
        }

        if (opcode == OP_0)
            return 0;
        else if (opcode == OP_1NEGATE)
            return -1;
        else
            return opcode + 1 - OP_1;
    }

    public static int encodeToOpN(int value) {
        if(value < -1 || value > 16) {
            throw new ProtocolException("encodeToOpN called for " + value + " which we cannot encode in an opcode.");
        }
        if (value == 0)
            return OP_0;
        else if (value == -1)
            return OP_1NEGATE;
        else
            return value - 1 + OP_1;
    }

    public static byte[] removeAllInstancesOfOp(byte[] inputScript, int opCode) {
        return removeAllInstancesOf(inputScript, new byte[] {(byte)opCode});
    }

    public static byte[] removeAllInstancesOf(byte[] inputScript, byte[] chunkToRemove) {
        // We usually don't end up removing anything
        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(inputScript.length);

        int cursor = 0;
        while (cursor < inputScript.length) {
            boolean skip = equalsRange(inputScript, cursor, chunkToRemove);

            int opcode = inputScript[cursor++] & 0xFF;
            int additionalBytes = 0;
            if (opcode >= 0 && opcode < OP_PUSHDATA1) {
                additionalBytes = opcode;
            } else if (opcode == OP_PUSHDATA1) {
                additionalBytes = (0xFF & inputScript[cursor]) + 1;
            } else if (opcode == OP_PUSHDATA2) {
                additionalBytes = Utils.readUint16(inputScript, cursor) + 2;
            } else if (opcode == OP_PUSHDATA4) {
                additionalBytes = (int) Utils.readUint32(inputScript, cursor) + 4;
            }
            if (!skip) {
                try {
                    bos.write(opcode);
                    bos.write(Arrays.copyOfRange(inputScript, cursor, cursor + additionalBytes));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            cursor += additionalBytes;
        }
        return bos.toByteArray();
    }

    private static boolean equalsRange(byte[] a, int start, byte[] b) {
        if (start + b.length > a.length)
            return false;
        for (int i = 0; i < b.length; i++)
            if (a[i + start] != b[i])
                return false;
        return true;
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        for(ScriptChunk chunk : chunks) {
            builder.append(chunk.toString());
            builder.append(" ");
        }

        return builder.toString().trim();
    }

    public String toDisplayString() {
        StringBuilder builder = new StringBuilder();
        int signatureCount = 1;
        int pubKeyCount = 1;
        for(ScriptChunk chunk : chunks) {
            if(chunk.isSignature()) {
                builder.append("<signature").append(signatureCount++).append(">");
            } else if(chunk.isScript()) {
                Script nestedScript = new Script(chunk.getData());
                if(ScriptPattern.isP2WPKH(nestedScript)) {
                    builder.append("(OP_0 <wpkh>)");
                } else if(ScriptPattern.isP2WSH(nestedScript)) {
                    builder.append("(OP_0 <wsh>)");
                } else {
                    builder.append("(").append(nestedScript.toDisplayString()).append(")");
                }
            } else if(chunk.isPubKey()) {
                builder.append("<pubkey").append(pubKeyCount++).append(">");
            } else {
                builder.append(chunk.toString());
            }

            builder.append(" ");
        }

        return builder.toString().trim();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return Arrays.equals(getQuickProgram(), ((Script)o).getQuickProgram());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getQuickProgram());
    }

    // Utility that doesn't copy for internal use
    private byte[] getQuickProgram() {
        if (program != null)
            return program;
        return getProgram();
    }
}
