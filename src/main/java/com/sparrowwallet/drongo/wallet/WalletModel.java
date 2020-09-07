package com.sparrowwallet.drongo.wallet;

public enum WalletModel {
    SEED, SPARROW, BITCOIN_CORE, ELECTRUM, TREZOR_1, TREZOR_T, COLDCARD, LEDGER_NANO_S, LEDGER_NANO_X, DIGITALBITBOX_01, KEEPKEY, SPECTER;

    public static WalletModel getModel(String model) {
        return valueOf(model.toUpperCase());
    }

    public String getType() {
        if(this == TREZOR_1 || this == TREZOR_T) {
            return "trezor";
        }

        if(this == LEDGER_NANO_S || this == LEDGER_NANO_X) {
            return "ledger";
        }

        if(this == DIGITALBITBOX_01) {
            return "digitalbitbox";
        }

        return this.toString().toLowerCase();
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
        String line = this.toString().toLowerCase();
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
