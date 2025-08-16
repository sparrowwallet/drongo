package com.sparrowwallet.drongo.protocol;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Block extends Message {
    private BlockHeader blockHeader;
    private Sha256Hash hash;
    private List<Transaction> transactions;

    public Block(byte[] payload) {
        super(payload, 0);
    }

    public void parse() {
        blockHeader = new BlockHeader(payload, cursor);
        cursor += blockHeader.getMessageSize();

        hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(payload, offset, cursor - offset));
        if(cursor != payload.length) {
            int numTransactions = (int)readVarInt();
            transactions = new ArrayList<>(numTransactions);
            for(int i = 0; i < numTransactions; i++) {
                Transaction tx = new Transaction(payload, cursor);
                transactions.add(tx);
                cursor += tx.getMessageSize();
            }
        } else {
            transactions = Collections.emptyList();
        }
    }

    public BlockHeader getBlockHeader() {
        return blockHeader;
    }

    public Sha256Hash getHash() {
        return hash;
    }

    public List<Transaction> getTransactions() {
        return transactions;
    }
}
