package com.sparrowwallet.drongo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.*;

public class Main {
    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String [] args) {
        String propertiesFile = "./drongo.properties";
        if(args.length > 0) {
            propertiesFile = args[0];
        }

        Properties properties = new Properties();
        properties.setProperty("nodeAddress", "localhost");

        try {
            File file = new File(propertiesFile);
            properties.load(new FileInputStream(propertiesFile));
            log.info("Loaded properties from " + file.getCanonicalPath());
        } catch (IOException e) {
            log.error("Could not load properties from provided path " + propertiesFile);
        }

        String nodeZmqAddress = properties.getProperty("node.zmqpubrawtx");
        if(nodeZmqAddress == null) {
            log.error("Property node.zmqpubrawtx not set, provide the zmqpubrawtx setting of the local node");
            System.exit(1);
        }

        Map<String, String> rpcConnection = new LinkedHashMap<String, String>() {
            {
                put("host", properties.getProperty("node.rpcconnect", "127.0.0.1"));
                put("port", properties.getProperty("node.rpcport", "8332"));
                put("user", properties.getProperty("node.rpcuser"));
                put("password", properties.getProperty("node.rpcpassword"));
            }
        };

        List<WatchWallet> watchWallets = new ArrayList<>();
        int walletNumber = 1;
        WatchWallet wallet = getWalletFromProperties(properties, walletNumber);
        if(wallet == null) {
            log.error("Property wallet.name.1 and/or wallet.descriptor.1 not set, provide wallet name and Base58 encoded key starting with xpub or ypub");
            System.exit(1);
        }
        while(wallet != null) {
            watchWallets.add(wallet);
            wallet = getWalletFromProperties(properties, ++walletNumber);
        }

        String notifyRecipients = properties.getProperty("notify.recipients");
        if(notifyRecipients == null) {
            log.error("Property notify.recipients not set, provide comma separated email addresses to receive wallet change notifications");
            System.exit(1);
        }

        Drongo drongo = new Drongo(nodeZmqAddress, rpcConnection, watchWallets, notifyRecipients.split(","));
        drongo.start();
    }

    private static WatchWallet getWalletFromProperties(Properties properties, int walletNumber) {
        String walletName = properties.getProperty("wallet.name." + walletNumber);
        String walletDescriptor = properties.getProperty("wallet.descriptor." + walletNumber);
        if(walletName != null && walletDescriptor != null) {
            return new WatchWallet(walletName, walletDescriptor);
        }

        return null;
    }
}
