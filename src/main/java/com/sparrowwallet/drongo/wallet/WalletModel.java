package com.sparrowwallet.drongo.wallet;

import java.util.Locale;

public enum WalletModel {
    SEED, SPARROW, BITCOIN_CORE, ELECTRUM, TREZOR_1, TREZOR_T, COLDCARD, LEDGER_NANO_S, LEDGER_NANO_X, DIGITALBITBOX_01, KEEPKEY, SPECTER_DESKTOP, COBO_VAULT, BITBOX_02, SPECTER_DIY, PASSPORT, BLUE_WALLET, KEYSTONE, SEEDSIGNER, CARAVAN, GORDIAN_SEED_TOOL, JADE, LEDGER_NANO_S_PLUS, EPS;

    public static WalletModel getModel(String model) {
        return valueOf(model.toUpperCase(Locale.ROOT));
    }

    public String getType() {
        if(this == TREZOR_1 || this == TREZOR_T) {
            return "trezor";
        }

        if(this == LEDGER_NANO_S || this == LEDGER_NANO_X || this == LEDGER_NANO_S_PLUS) {
            return "ledger";
        }

        if(this == DIGITALBITBOX_01) {
            return "digitalbitbox";
        }

        if(this == BITCOIN_CORE) {
            return "bitcoincore";
        }

        if(this == BITBOX_02) {
            return "bitbox02";
        }

        if(this == COBO_VAULT) {
            return "cobovault";
        }

        if(this == SPECTER_DESKTOP || this == SPECTER_DIY) {
            return "specter";
        }

        if(this == BLUE_WALLET) {
            return "bluewallet";
        }

        if(this == GORDIAN_SEED_TOOL) {
            return "seedtool";
        }

        return this.toString().toLowerCase(Locale.ROOT);
    }

    public boolean alwaysIncludeNonWitnessUtxo() {
        if(this == COLDCARD || this == COBO_VAULT || this == PASSPORT || this == KEYSTONE || this == GORDIAN_SEED_TOOL) {
            return false;
        }

        return true;
    }

    public boolean requiresPinPrompt() {
        return (this == TREZOR_1 || this == KEEPKEY);
    }

    public boolean externalPassphraseEntry() {
        return (this == TREZOR_1 || this == KEEPKEY);
    }

    public static WalletModel fromType(String type) {
        for(WalletModel model : values()) {
            if(model.getType().equalsIgnoreCase(type)) {
                return model;
            }
        }

        return null;
    }

    public String toDisplayString() {
        String line = this.toString().toLowerCase(Locale.ROOT);
        String[] words = line.split("_");
        StringBuilder builder = new StringBuilder();
        for(String word : words) {
            if(word.equals("1")) {
                word = "one";
            }
            builder.append(Character.toUpperCase(word.charAt(0)));
            builder.append(word.substring(1));
            builder.append(" ");
        }

        return builder.toString().trim();
    }
}
