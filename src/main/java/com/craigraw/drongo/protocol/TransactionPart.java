package com.craigraw.drongo.protocol;

import com.craigraw.drongo.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;

public abstract class TransactionPart {
    private static final Logger log = LoggerFactory.getLogger(TransactionPart.class);

    public static final int MAX_SIZE = 0x02000000; // 32MB
    public static final int UNKNOWN_LENGTH = Integer.MIN_VALUE;

    protected byte[] rawtx;

    // The offset is how many bytes into the provided byte array this message payload starts at.
    protected int offset;
    // The cursor keeps track of where we are in the byte array as we parse it.
    // Note that it's relative to the start of the array NOT the start of the message payload.
    protected int cursor;

    protected TransactionPart parent;

    protected int length = UNKNOWN_LENGTH;

    public TransactionPart(byte[] rawtx, int offset) {
        this.rawtx = rawtx;
        this.cursor = this.offset = offset;

        parse();
    }

    protected abstract void parse() throws ProtocolException;

    public final void setParent(TransactionPart parent) {
        this.parent = parent;
    }

    /**
     * This returns a correct value by parsing the message.
     */
    public final int getMessageSize() {
        if (length == UNKNOWN_LENGTH) {
            throw new ProtocolException();
        }

        return length;
    }

    protected long readUint32() throws ProtocolException {
        try {
            long u = Utils.readUint32(rawtx, cursor);
            cursor += 4;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected long readInt64() throws ProtocolException {
        try {
            long u = Utils.readInt64(rawtx, cursor);
            cursor += 8;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected byte[] readBytes(int length) throws ProtocolException {
        if ((length > MAX_SIZE) || (cursor + length > rawtx.length)) {
            throw new ProtocolException("Claimed value length too large: " + length);
        }
        try {
            byte[] b = new byte[length];
            System.arraycopy(rawtx, cursor, b, 0, length);
            cursor += length;
            return b;
        } catch (IndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected long readVarInt() throws ProtocolException {
        return readVarInt(0);
    }

    protected long readVarInt(int offset) throws ProtocolException {
        try {
            VarInt varint = new VarInt(rawtx, cursor + offset);
            cursor += offset + varint.getOriginalSizeInBytes();
            return varint.value;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected Sha256Hash readHash() throws ProtocolException {
        // We have to flip it around, as it's been read off the wire in little endian.
        // Not the most efficient way to do this but the clearest.
        return Sha256Hash.wrapReversed(readBytes(32));
    }

    public final void bitcoinSerialize(OutputStream stream) throws IOException {
        // 1st check for cached bytes.
        if (rawtx != null && length != UNKNOWN_LENGTH) {
            stream.write(rawtx, offset, length);
            return;
        }

        bitcoinSerializeToStream(stream);
    }

    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        log.error("Error: {} class has not implemented bitcoinSerializeToStream method.  Generating message with no payload", getClass());
    }
}
