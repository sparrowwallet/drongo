package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.protocol.Network;
import com.sparrowwallet.drongo.rpc.BitcoinJSONRPCClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Drongo {
    private static final Logger log = LoggerFactory.getLogger(Drongo.class);

    private Network network;
    private String nodeZmqAddress;
    private BitcoinJSONRPCClient bitcoinJSONRPCClient;
    private List<WatchWallet> watchWallets;
    private String[] notifyRecipients;

    public Drongo(Network network, String nodeZmqAddress, Map<String, String> nodeRpc, List<WatchWallet> watchWallets, String[] notifyRecipients) {
        this.network = network;
        this.nodeZmqAddress = nodeZmqAddress;
        this.bitcoinJSONRPCClient = new BitcoinJSONRPCClient(nodeRpc.get("host"), nodeRpc.get("port"), nodeRpc.get("user"), nodeRpc.get("password"));
        this.watchWallets = watchWallets;
        this.notifyRecipients = notifyRecipients;

        for(WatchWallet wallet : watchWallets) {
            wallet.initialiseAddresses();
        }
    }

    public void start() {
        ExecutorService executorService = null;

        try {
            executorService = Executors.newFixedThreadPool(2);

            try (ZContext context = new ZContext()) {
                ZMQ.Socket subscriber = context.createSocket(SocketType.SUB);
                subscriber.setRcvHWM(0);
                subscriber.connect(nodeZmqAddress);

                String subscription = "rawtx";
                subscriber.subscribe(subscription.getBytes(ZMQ.CHARSET));

                while (true) {
                    String topic = subscriber.recvStr();
                    if (topic == null)
                        break;
                    byte[] data = subscriber.recv();
                    assert (topic.equals(subscription));

                    if(subscriber.hasReceiveMore()) {
                        byte[] endData = subscriber.recv();
                    }

                    TransactionTask transactionTask = new TransactionTask(this, data);
                    executorService.submit(transactionTask);
                }
            }
        } finally {
            if(executorService != null) {
                executorService.shutdown();
            }
        }
    }

    public Network getNetwork() {
        return network;
    }

    public BitcoinJSONRPCClient getBitcoinJSONRPCClient() {
        return bitcoinJSONRPCClient;
    }

    public List<WatchWallet> getWallets() {
        return watchWallets;
    }
}
