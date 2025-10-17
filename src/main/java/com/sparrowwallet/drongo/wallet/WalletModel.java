package com.sparrowwallet.drongo.wallet;

import java.util.Locale;

public enum WalletModel {
    SEED, SPARROW, BITCOIN_CORE, ELECTRUM, TREZOR_1, TREZOR_T, COLDCARD, LEDGER_NANO_S, LEDGER_NANO_X, DIGITALBITBOX_01, KEEPKEY, SPECTER_DESKTOP, COBO_VAULT,
    BITBOX_02, SPECTER_DIY, PASSPORT, BLUE_WALLET, KEYSTONE, SEEDSIGNER, CARAVAN, GORDIAN_SEED_TOOL, JADE, LEDGER_NANO_S_PLUS, EPS, TAPSIGNER, SATSCARD, LABELS,
    BSMS, KRUX, SATOCHIP, TRANSACTIONS, AIRGAP_VAULT, TREZOR_SAFE_3, SATSCHIP, SAMOURAI, TREZOR_SAFE_5, LEDGER_STAX, LEDGER_FLEX, ONEKEY_CLASSIC_1S, ONEKEY_PRO,
    KEYCARD_SHELL, KEYCARD;

    public static WalletModel getModel(String model) {
        return valueOf(model.toUpperCase(Locale.ROOT));
    }

    public String getType() {
        if(this == TREZOR_1 || this == TREZOR_T || this == TREZOR_SAFE_3 || this == TREZOR_SAFE_5) {
            return "trezor";
        }

        if(this == LEDGER_NANO_S || this == LEDGER_NANO_X || this == LEDGER_NANO_S_PLUS || this == LEDGER_STAX || this == LEDGER_FLEX) {
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

        if(this == AIRGAP_VAULT) {
            return "airgapvault";
        }

        if(this == ONEKEY_CLASSIC_1S || this == ONEKEY_PRO) {
            return "onekey";
        }

        if(this == KEYCARD_SHELL || this == KEYCARD) {
            return "keycard";
        }

        return this.toString().toLowerCase(Locale.ROOT);
    }

    public boolean alwaysIncludeNonWitnessUtxo() {
        if(this == COLDCARD || this == COBO_VAULT || this == PASSPORT || this == KEYSTONE || this == GORDIAN_SEED_TOOL || this == SEEDSIGNER || this == KRUX || this == JADE ||
           this == TAPSIGNER || this == SATOCHIP || this == KEYCARD_SHELL || this == KEYCARD) {
            return false;
        }

        return true;
    }

    public boolean requiresPinPrompt() {
        return (this == TREZOR_1 || this == KEEPKEY || this == ONEKEY_CLASSIC_1S);
    }

    public boolean externalPassphraseEntry() {
        return (this == TREZOR_1 || this == KEEPKEY || this == ONEKEY_CLASSIC_1S);
    }

    public boolean isCard() {
        return (this == TAPSIGNER || this == SATSCHIP || this == SATSCARD || this == SATOCHIP || this == KEYCARD);
    }

    public boolean hasUsb() {
        return (this == TREZOR_1 || this == TREZOR_T || this == TREZOR_SAFE_3 || this == TREZOR_SAFE_5 || this == LEDGER_NANO_S || this == LEDGER_NANO_X || this == LEDGER_NANO_S_PLUS ||
                this == LEDGER_STAX || this == LEDGER_FLEX || this == DIGITALBITBOX_01 || this == BITBOX_02 || this == COLDCARD || this == KEEPKEY || this == JADE || this == ONEKEY_CLASSIC_1S || this == ONEKEY_PRO);
    }

    public int getMinPinLength() {
        if(this == SATOCHIP) {
            return 4;
        } else {
            return 6;
        }
    }

    public int getMaxPinLength() {
        if(this == KEYCARD) {
            return 6;
        } else if(this == SATOCHIP) {
            return 16;
        } else {
            return 32;
        }
    }

    public boolean hasDefaultPin() {
        if(this == SATOCHIP) {
            return false;
        } else {
            return true;
        }
    }

    public boolean hasZeroInPin() {
        if(this == ONEKEY_CLASSIC_1S) {
            return true;
        } else {
            return false;
        }
    }

    public boolean requiresSeedInitialization() {
        if(this == SATOCHIP || this == KEYCARD) {
            return true;
        } else {
            return false;
        }
    }

    public boolean supportsBackup() {
        if(this == SATOCHIP || this == SATSCHIP || this == KEYCARD) {
            return false;
        } else {
            return true;
        }
    }

    public boolean showLegacyQR() {
        if(this == COBO_VAULT) {
            return true;
        } else {
            return false;
        }
    }

    public boolean showBbqr() {
        if(this == COLDCARD || this == SPARROW || this == KRUX) {
            return true;
        } else {
            return false;
        }
    }

    public boolean selectBbqr() {
        if(this == COLDCARD) {
            return true;
        } else {
            return false;
        }
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
            } else if(Character.isDigit(word.charAt(0))) {
                word = word.toUpperCase(Locale.ROOT);
            } else if(BITBOX_02.getType().startsWith(word)) {
                word = "BitBox";
            } else if(word.equals(ONEKEY_PRO.getType())) {
                word = "OneKey";
            } else if(word.equals("diy")) {
                word = "DIY";
            }
            builder.append(Character.toUpperCase(word.charAt(0)));
            builder.append(word.substring(1));
            if(this != BLUE_WALLET) {
                builder.append(" ");
            }
        }

        return builder.toString().trim();
    }
}
