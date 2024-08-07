package com.sparrowwallet.drongo.wallet;

public class MnemonicException extends Exception {
    private final String title;

    public MnemonicException() {
        super();
        this.title = null;
    }

    public MnemonicException(String message) {
        this(message, message);
    }

    public MnemonicException(String title, String message) {
        super(message);
        this.title = title;
    }

    public String getTitle() {
        return title;
    }

    /**
     * Thrown when an argument to MnemonicCode is the wrong length.
     */
    public static class MnemonicLengthException extends MnemonicException {
        public MnemonicLengthException(String message) {
            super(message);
        }

        public MnemonicLengthException(String title, String message) {
            super(title, message);
        }
    }

    /**
     * Thrown when a list of MnemonicCode words fails the checksum check.
     */
    public static class MnemonicChecksumException extends MnemonicException {
        public MnemonicChecksumException() {
            super();
        }

        public MnemonicChecksumException(String title, String message) {
            super(title, message);
        }
    }

    /**
     * Thrown when a word is encountered which is not in the MnemonicCode's word list.
     */
    public static class MnemonicWordException extends MnemonicException {
        /** Contains the word that was not found in the word list. */
        public final String badWord;

        public MnemonicWordException(String badWord) {
            super();
            this.badWord = badWord;
        }
    }

    /**
     * Thrown when the mnemonic is valid, but for for the expected standard
     */
    public static class MnemonicTypeException extends MnemonicException {
        public final DeterministicSeed.Type invalidType;

        public MnemonicTypeException(DeterministicSeed.Type invalidType) {
            super();
            this.invalidType = invalidType;
        }
    }
}
