package com.sparrowwallet.drongo.wallet;

public enum WalletModel {
    SPARROW, BITCOIN_CORE, ELECTRUM, TREZOR_1, TREZOR_T, COLDCARD, LEDGER, DIGITALBITBOX, KEEPKEY;

    public static WalletModel getModel(String model) {
        return valueOf(model.toUpperCase());
    }

    public String getType() {
        if(this == TREZOR_1 || this == TREZOR_T) {
            return "trezor";
        }

        return this.toString();
    }

    public static WalletModel fromType(String type) {
        for(WalletModel model : values()) {
            if(model.getType().equals(type)) {
                return model;
            }
        }

        return null;
    }

    public String toDisplayString() {
        String line = this.toString().toLowerCase();
        String[] words = line.split("_");
        StringBuilder builder = new StringBuilder();
        for(String word : words) {
            builder.append(Character.toUpperCase(word.charAt(0)));
            builder.append(word.substring(1));
            builder.append(" ");
        }

        return builder.toString().trim();
    }
}
