package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.protocol.*;
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
                    try {
                        Address[] inputAddresses = referencedOutput.getScript().getToAddresses(drongo.getNetwork());
                        input.getOutpoint().setAddresses(inputAddresses);
                        inputJoiner.add((inputAddresses.length == 1 ? inputAddresses[0] : Arrays.asList(inputAddresses)) + ":" + vin);
                    } catch(NonStandardScriptException e) {
                        //Cannot happen
                    }
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
                    try {
                        Address[] outputAddresses = output.getScript().getToAddresses(drongo.getNetwork());
                        output.setAddresses(outputAddresses);
                        outputJoiner.add((outputAddresses.length == 1 ? outputAddresses[0] : Arrays.asList(outputAddresses)) + ":" + vout + " (" + output.getValue() + ")");
                    } catch(NonStandardScriptException e) {
                        //Cannot happen
                    }
                }
            } catch(ProtocolException e) {
                log.debug("Invalid script for output " + vout + " detected (" + e.getMessage() + "). Skipping...");
            }

            vout++;
        }

        builder.append(outputJoiner.toString());
        log.debug(builder.toString());

        checkWallet(transaction);
    }

    private void checkWallet(Transaction transaction) {
        for(WatchWallet wallet : drongo.getWallets()) {
            List<Address> fromAddresses = new ArrayList<>();
            for(TransactionInput input : transaction.getInputs()) {
                for(Address address : input.getOutpoint().getAddresses()) {
                    if(wallet.containsAddress(address)) {
                        fromAddresses.add(address);
                    }
                }
            }

            Map<Address,Long> toAddresses = new HashMap<>();
            for(TransactionOutput output : transaction.getOutputs()) {
                for(Address address : output.getAddresses()) {
                    if(wallet.containsAddress(address)) {
                        toAddresses.put(address, output.getValue());
                    }
                }
            }

            if(!fromAddresses.isEmpty()) {
                StringBuilder builder = new StringBuilder();
                builder.append("Wallet ").append(wallet.getName()).append(" sent from address").append(fromAddresses.size() == 1 ? " " : "es ");
                StringJoiner fromJoiner = new StringJoiner(", ", "[", "]");
                for(Address address : fromAddresses) {
                    fromJoiner.add(address.toString() + " [" + Utils.formatHDPath(wallet.getAddressPath(address)) + "]");
                }
                builder.append(fromJoiner.toString()).append(" in txid ").append(transaction.getTxId());
                log.info(builder.toString());
            }

            if(!toAddresses.isEmpty()) {
                StringBuilder builder = new StringBuilder();
                builder.append("Wallet ").append(wallet.getName()).append(" received to address").append(toAddresses.size() == 1 ? " " : "es ");
                StringJoiner toJoiner = new StringJoiner(", ", "[", "]");
                for(Address address : toAddresses.keySet()) {
                    toJoiner.add(address.toString() + " [" + Utils.formatHDPath(wallet.getAddressPath(address)) + "]" + " (" + toAddresses.get(address) + " sats)");
                }
                builder.append(toJoiner.toString()).append(" in txid ").append(transaction.getTxId());
                log.info(builder.toString());
            }
        }
    }
}
