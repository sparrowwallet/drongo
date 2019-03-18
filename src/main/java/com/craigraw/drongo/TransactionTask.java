package com.craigraw.drongo;

import com.craigraw.drongo.address.Address;
import com.craigraw.drongo.protocol.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class TransactionTask implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(Drongo.class);

    private Drongo drongo;
    private byte[] transactionData;

    public TransactionTask(Drongo drongo, byte[] transactionData) {
        this.drongo = drongo;
        this.transactionData = transactionData;
    }

    @Override
    public void run() {
        Transaction transaction = new Transaction(transactionData);
        Map<String, Transaction> referencedTransactions = new HashMap<>();

        Sha256Hash txid = transaction.getTxId();
        StringBuilder builder = new StringBuilder("Txid: " + txid.toString() + " ");
        StringJoiner inputJoiner = new StringJoiner(", ", "[", "]");

        int vin = 0;
        for(TransactionInput input : transaction.getInputs()) {
            if(input.isCoinBase()) {
                inputJoiner.add("Coinbase:" + vin);
            } else {
                String referencedTxID = input.getOutpoint().getHash().toString();
                long referencedVout = input.getOutpoint().getIndex();

                Transaction referencedTransaction = referencedTransactions.get(referencedTxID);
                if(referencedTransaction == null) {
                    String referencedTransactionHex = drongo.getBitcoinJSONRPCClient().getRawTransaction(referencedTxID);
                    referencedTransaction = new Transaction(Utils.hexToBytes(referencedTransactionHex));
                    referencedTransactions.put(referencedTxID, referencedTransaction);
                }

                TransactionOutput referencedOutput = referencedTransaction.getOutputs().get((int)referencedVout);
                if(referencedOutput.getScript().containsToAddress()) {
                    Address[] inputAddresses = referencedOutput.getScript().getToAddresses();
                    input.getOutpoint().setAddresses(inputAddresses);
                    inputJoiner.add((inputAddresses.length == 1 ? inputAddresses[0] : Arrays.asList(inputAddresses)) + ":" + vin);
                } else {
                    log.warn("Could not determine nature of referenced input tx: " + referencedTxID + ":" + referencedVout);
                }
            }

            vin++;
        }

        builder.append(inputJoiner.toString() + " => ");
        StringJoiner outputJoiner = new StringJoiner(", ", "[", "]");

        int vout = 0;
        for(TransactionOutput output : transaction.getOutputs()) {
            try {
                if(output.getScript().containsToAddress()) {
                    Address[] outputAddresses = output.getScript().getToAddresses();
                    output.setAddresses(outputAddresses);
                    outputJoiner.add((outputAddresses.length == 1 ? outputAddresses[0] : Arrays.asList(outputAddresses)) + ":" + vout + " (" + output.getValue() + ")");
                }
            } catch(ProtocolException e) {
                log.debug("Invalid script for output " + vout + " detected (" + e.getMessage() + "). Skipping...");
            }

            vout++;
        }

        builder.append(outputJoiner.toString());
        log.info(builder.toString() + " " + transaction.getAllAddresses());
    }
}
