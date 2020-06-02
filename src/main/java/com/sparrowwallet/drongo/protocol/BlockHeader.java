package com.sparrowwallet.drongo.protocol;

import java.util.Date;

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
}
