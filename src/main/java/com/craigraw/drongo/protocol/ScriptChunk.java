package com.craigraw.drongo.protocol;

import com.craigraw.drongo.Utils;

import java.io.IOException;
import java.io.OutputStream;

import static com.craigraw.drongo.protocol.ScriptOpCodes.*;

public class ScriptChunk {
    /** Operation to be executed. Opcodes are defined in {@link ScriptOpCodes}. */
    public final int opcode;

    /**
     * For push operations, this is the vector to be pushed on the stack. For {@link ScriptOpCodes#OP_0}, the vector is
     * empty. Null for non-push operations.
     */
    public final byte[] data;

    private int startLocationInProgram;

    public ScriptChunk(int opcode, byte[] data) {
        this(opcode, data, -1);
    }

    public ScriptChunk(int opcode, byte[] data, int startLocationInProgram) {
        this.opcode = opcode;
        this.data = data;
        this.startLocationInProgram = startLocationInProgram;
    }

    public boolean equalsOpCode(int opcode) {
        return opcode == this.opcode;
    }

    /**
     * If this chunk is a single byte of non-pushdata content (could be OP_RESERVED or some invalid Opcode)
     */
    public boolean isOpCode() {
        return opcode > OP_PUSHDATA4;
    }

    public void write(OutputStream stream) throws IOException {
        if (isOpCode()) {
            if(data != null) throw new IllegalStateException("Data must be null for opcode chunk");
            stream.write(opcode);
        } else if (data != null) {
            if (opcode < OP_PUSHDATA1) {
                if(data.length != opcode) throw new IllegalStateException("Data length must equal opcode value");
                stream.write(opcode);
            } else if (opcode == OP_PUSHDATA1) {
                if(data.length > 0xFF) throw new IllegalStateException("Data length must be less than or equal to 256");
                stream.write(OP_PUSHDATA1);
                stream.write(data.length);
            } else if (opcode == OP_PUSHDATA2) {
                if(data.length > 0xFFFF) throw new IllegalStateException("Data length must be less than or equal to 65536");
                stream.write(OP_PUSHDATA2);
                Utils.uint16ToByteStreamLE(data.length, stream);
            } else if (opcode == OP_PUSHDATA4) {
                if(data.length > Script.MAX_SCRIPT_ELEMENT_SIZE) throw new IllegalStateException("Data length must be less than or equal to " + Script.MAX_SCRIPT_ELEMENT_SIZE);
                stream.write(OP_PUSHDATA4);
                Utils.uint32ToByteStreamLE(data.length, stream);
            } else {
                throw new RuntimeException("Unimplemented");
            }
            stream.write(data);
        } else {
            stream.write(opcode); // smallNum
        }
    }
}
