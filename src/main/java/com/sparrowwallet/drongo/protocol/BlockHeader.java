package com.sparrowwallet.drongo.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import static com.sparrowwallet.drongo.Utils.uint32ToByteStreamLE;

public class BlockHeader extends Message {
    private long version;
    private Sha256Hash prevBlockHash;
    private Sha256Hash merkleRoot, witnessRoot;
    private long time;
    private long difficultyTarget; // "nBits"
    private long nonce;

    public BlockHeader(byte[] rawheader) {
        super(rawheader, 0);
    }

    public BlockHeader(long version, Sha256Hash prevBlockHash, Sha256Hash merkleRoot, Sha256Hash witnessRoot, long time, long difficultyTarget, long nonce) {
        this.version = version;
        this.prevBlockHash = prevBlockHash;
        this.merkleRoot = merkleRoot;
        this.witnessRoot = witnessRoot;
        this.time = time;
        this.difficultyTarget = difficultyTarget;
        this.nonce = nonce;
    }

    @Override
    protected void parse() throws ProtocolException {
        version = readUint32();
        prevBlockHash = readHash();
        merkleRoot = readHash();
        time = readUint32();
        difficultyTarget = readUint32();
        nonce = readUint32();

        length = cursor - offset;
    }

    public long getVersion() {
        return version;
    }

    public Sha256Hash getPrevBlockHash() {
        return prevBlockHash;
    }

    public Sha256Hash getMerkleRoot() {
        return merkleRoot;
    }

    public Sha256Hash getWitnessRoot() {
        return witnessRoot;
    }

    public long getTime() {
        return time;
    }

    public Date getTimeAsDate() {
        return new Date(time * 1000);
    }

    public long getDifficultyTarget() {
        return difficultyTarget;
    }

    public long getNonce() {
        return nonce;
    }

    public byte[] bitcoinSerialize() {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            bitcoinSerializeToStream(outputStream);
            return outputStream.toByteArray();
        } catch (IOException e) {
            //can't happen
        }

        return null;
    }

    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        uint32ToByteStreamLE(version, stream);
        stream.write(prevBlockHash.getReversedBytes());
        stream.write(merkleRoot.getReversedBytes());
        uint32ToByteStreamLE(time, stream);
        uint32ToByteStreamLE(difficultyTarget, stream);
        uint32ToByteStreamLE(nonce, stream);
    }
}
