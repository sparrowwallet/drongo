package com.sparrowwallet.drongo;

import java.util.Locale;

public enum Network {
    MAINNET("mainnet", "Mainnet", "mainnet", 0, "1", 5, "3", "bc", "sp", ExtendedKey.Header.xprv, ExtendedKey.Header.xpub, 128, 8332),
    TESTNET("testnet", "Testnet3", "testnet3", 111, "mn", 196, "2", "tb", "tsp", ExtendedKey.Header.tprv, ExtendedKey.Header.tpub, 239, 18332),
    REGTEST("regtest", "Regtest", "regtest", 111, "mn", 196, "2", "bcrt", "sprt", ExtendedKey.Header.tprv, ExtendedKey.Header.tpub, 239, 18443),
    SIGNET("signet", "Signet", "signet", 111, "mn", 196, "2", "tb", "tsp", ExtendedKey.Header.tprv, ExtendedKey.Header.tpub, 239, 38332),
    TESTNET4("testnet4", "Testnet4", "testnet4", 111, "mn", 196, "2", "tb", "tsp", ExtendedKey.Header.tprv, ExtendedKey.Header.tpub, 239, 48332);

    public static final String BLOCK_HEIGHT_PROPERTY = "com.sparrowwallet.blockHeight";
    private static final Network[] CANONICAL_VALUES = new Network[]{MAINNET, TESTNET, REGTEST, SIGNET};

    Network(String name, String displayName, String home, int p2pkhAddressHeader, String p2pkhAddressPrefix, int p2shAddressHeader, String p2shAddressPrefix, String bech32AddressHrp, String spAddressHrp, ExtendedKey.Header xprvHeader, ExtendedKey.Header xpubHeader, int dumpedPrivateKeyHeader, int defaultPort) {
        this.name = name;
        this.displayName = displayName;
        this.home = home;
        this.p2pkhAddressHeader = p2pkhAddressHeader;
        this.p2pkhAddressPrefix = p2pkhAddressPrefix;
        this.p2shAddressHeader = p2shAddressHeader;
        this.p2shAddressPrefix = p2shAddressPrefix;
        this.bech32AddressHrp = bech32AddressHrp;
        this.spAddressHrp = spAddressHrp;
        this.xprvHeader = xprvHeader;
        this.xpubHeader = xpubHeader;
        this.dumpedPrivateKeyHeader = dumpedPrivateKeyHeader;
        this.defaultPort = defaultPort;
    }

    private final String name;
    private final String displayName;
    private final String home;
    private final int p2pkhAddressHeader;
    private final String p2pkhAddressPrefix;
    private final int p2shAddressHeader;
    private final String p2shAddressPrefix;
    private final String bech32AddressHrp;
    private final String spAddressHrp;
    private final ExtendedKey.Header xprvHeader;
    private final ExtendedKey.Header xpubHeader;
    private final int dumpedPrivateKeyHeader;
    private final int defaultPort;

    private static Network currentNetwork;

    public String getName() {
        return name;
    }

    public String getCapitalizedName() {
        return name.substring(0, 1).toUpperCase(Locale.ROOT) + name.substring(1);
    }

    public String toDisplayString() {
        return displayName;
    }

    public String getHome() {
        return home;
    }

    public int getP2PKHAddressHeader() {
        return p2pkhAddressHeader;
    }

    public int getP2SHAddressHeader() {
        return p2shAddressHeader;
    }

    public String getBech32AddressHRP() {
        return bech32AddressHrp;
    }

    public String getSilentPaymentsAddressHrp() {
        return spAddressHrp;
    }

    public ExtendedKey.Header getXprvHeader() {
        return xprvHeader;
    }

    public ExtendedKey.Header getXpubHeader() {
        return xpubHeader;
    }

    public int getDumpedPrivateKeyHeader() {
        return dumpedPrivateKeyHeader;
    }

    public int getDefaultPort() {
        return defaultPort;
    }

    public boolean hasP2PKHAddressPrefix(String address) {
        for(String prefix : p2pkhAddressPrefix.split("")) {
            if(address.startsWith(prefix)) {
                return true;
            }
        }

        return false;
    }

    public boolean hasP2SHAddressPrefix(String address) {
        return address.startsWith(p2shAddressPrefix);
    }

    public static Network get() {
        if(currentNetwork == null) {
            currentNetwork = MAINNET;
        }

        return currentNetwork;
    }

    public static Network getCanonical() {
        return get() == TESTNET4 ? TESTNET : get();
    }

    public static Network[] canonicalValues() {
        return CANONICAL_VALUES;
    }

    public static void set(Network network) {
        if(currentNetwork != null && network != currentNetwork && !isTest()) {
            throw new IllegalStateException("Network already set to " + currentNetwork.getName());
        }

        currentNetwork = network;
    }

    private static boolean isTest() {
        return System.getProperty("org.gradle.test.worker") != null;
    }

    @Override
    public String toString() {
        return getName();
    }
}
