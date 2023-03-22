package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.Pbkdf2KeyDeriver;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Bip39MnemonicCode {
    private static final Logger log = LoggerFactory.getLogger(Bip39MnemonicCode.class);

    private final ArrayList<String> wordList;

    private static final String BIP39_ENGLISH_RESOURCE_NAME = "/wordlist/bip39-english.txt";
    private static final String BIP39_ENGLISH_SHA256 = "ad90bf3beb7b0eb7e5acd74727dc0da96e0a280a258354e7293fb7e211ac03db";

    /** UNIX time for when the BIP39 standard was finalised. This can be used as a default seed birthday. */
    public static long BIP39_STANDARDISATION_TIME_SECS = 1381276800;

    private static final int PBKDF2_ROUNDS = 2048;

    public static Bip39MnemonicCode INSTANCE;

    static {
        try {
            INSTANCE = new Bip39MnemonicCode();
        } catch (RuntimeException e) {
            log.error("Failed to load word list", e);
        }
    }

    /** Initialise from the included word list. Won't work on Android. */
    public Bip39MnemonicCode() {
        this(openDefaultWords(), BIP39_ENGLISH_SHA256);
    }

    private static InputStream openDefaultWords() {
        InputStream stream = Bip39MnemonicCode.class.getResourceAsStream(BIP39_ENGLISH_RESOURCE_NAME);
        if(stream == null) {
            throw new RuntimeException(new FileNotFoundException(BIP39_ENGLISH_RESOURCE_NAME));
        }

        return stream;
    }

    /**
     * Creates an MnemonicCode object, initializing with words read from the supplied input stream.  If a wordListDigest
     * is supplied the digest of the words will be checked.
     */
    public Bip39MnemonicCode(InputStream wordstream, String wordListDigest) throws IllegalArgumentException {
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(wordstream, StandardCharsets.UTF_8));
            this.wordList = new ArrayList<>(2048);
            MessageDigest md = Sha256Hash.newDigest();
            String word;
            while ((word = br.readLine()) != null) {
                md.update(word.getBytes());
                this.wordList.add(word);
            }
            br.close();

            if (this.wordList.size() != 2048) {
                throw new IllegalArgumentException("Input stream did not contain 2048 words");
            }

            // If a wordListDigest is supplied check to make sure it matches.
            if (wordListDigest != null) {
                byte[] digest = md.digest();
                String hexdigest = Utils.bytesToHex(digest);
                if (!hexdigest.equals(wordListDigest)) {
                    throw new IllegalArgumentException("Wordlist digest mismatch");
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Error loading word list", e);
        }
    }

    /**
     * Gets the word list this code uses.
     */
    public List<String> getWordList() {
        return Collections.unmodifiableList(wordList);
    }

    /**
     * Convert mnemonic word list to seed.
     */
    public static byte[] toSeed(List<String> words, String passphrase) {
        if(passphrase == null) {
            passphrase = "";
        }

        // To create binary seed from mnemonic, we use PBKDF2 function
        // with mnemonic sentence (in UTF-8) used as a password and
        // string "mnemonic" + passphrase (again in UTF-8) used as a
        // salt. Iteration count is set to 2048 and HMAC-SHA512 is
        // used as a pseudo-random function. Desired length of the
        // derived key is 512 bits (= 64 bytes).
        //
        String mnemonic = String.join(" ", words);
        String salt = "mnemonic" + Normalizer.normalize(passphrase, Normalizer.Form.NFKD);

        Pbkdf2KeyDeriver keyDeriver = new Pbkdf2KeyDeriver(salt.getBytes(StandardCharsets.UTF_8), PBKDF2_ROUNDS);
        return keyDeriver.deriveKey(mnemonic).getKeyBytes();
    }

    /**
     * Convert mnemonic word list to original entropy value.
     */
    public byte[] toEntropy(List<String> words) throws MnemonicException.MnemonicLengthException, MnemonicException.MnemonicWordException, MnemonicException.MnemonicChecksumException {
        if (words.size() % 3 > 0) {
            throw new MnemonicException.MnemonicLengthException("Word list size must be multiple of three words.");
        }

        if (words.size() == 0) {
            throw new MnemonicException.MnemonicLengthException("Word list is empty.");
        }

        // Look up all the words in the list and construct the
        // concatenation of the original entropy and the checksum.
        //
        int concatLenBits = words.size() * 11;
        boolean[] concatBits = new boolean[concatLenBits];
        int wordindex = 0;
        for (String word : words) {
            // Find the words index in the wordlist.
            int ndx = Collections.binarySearch(this.wordList, word);
            if (ndx < 0) {
                throw new MnemonicException.MnemonicWordException(word);
            }
            // Set the next 11 bits to the value of the index.
            for (int ii = 0; ii < 11; ++ii) {
                concatBits[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0;
            }
            ++wordindex;
        }

        int checksumLengthBits = concatLenBits / 33;
        int entropyLengthBits = concatLenBits - checksumLengthBits;

        // Extract original entropy as bytes.
        byte[] entropy = new byte[entropyLengthBits / 8];
        for (int ii = 0; ii < entropy.length; ++ii) {
            for (int jj = 0; jj < 8; ++jj) {
                if (concatBits[(ii * 8) + jj]) {
                    entropy[ii] |= 1 << (7 - jj);
                }
            }
        }

        // Take the digest of the entropy.
        byte[] hash = Sha256Hash.hash(entropy);
        boolean[] hashBits = bytesToBits(hash);

        // Check all the checksum bits.
        for (int i = 0; i < checksumLengthBits; ++i) {
            if (concatBits[entropyLengthBits + i] != hashBits[i]) {
                throw new MnemonicException.MnemonicChecksumException();
            }
        }
        return entropy;
    }

    /**
     * Convert entropy data to mnemonic word list.
     */
    public List<String> toMnemonic(byte[] entropy) throws MnemonicException.MnemonicLengthException {
        if (entropy.length % 4 > 0) {
            throw new MnemonicException.MnemonicLengthException("Entropy length not multiple of 32 bits.");
        }
        if (entropy.length == 0) {
            throw new MnemonicException.MnemonicLengthException("Entropy is empty.");
        }
        // We take initial entropy of ENT bits and compute its
        // checksum by taking first ENT / 32 bits of its SHA256 hash.

        byte[] hash = Sha256Hash.hash(entropy);
        boolean[] hashBits = bytesToBits(hash);

        boolean[] entropyBits = bytesToBits(entropy);
        int checksumLengthBits = entropyBits.length / 32;

        // We append these bits to the end of the initial entropy.
        boolean[] concatBits = new boolean[entropyBits.length + checksumLengthBits];
        System.arraycopy(entropyBits, 0, concatBits, 0, entropyBits.length);
        System.arraycopy(hashBits, 0, concatBits, entropyBits.length, checksumLengthBits);

        // Next we take these concatenated bits and split them into
        // groups of 11 bits. Each group encodes number from 0-2047
        // which is a position in a wordlist.  We convert numbers into
        // words and use joined words as mnemonic sentence.

        ArrayList<String> words = new ArrayList<>();
        int nwords = concatBits.length / 11;
        for (int i = 0; i < nwords; ++i) {
            int index = 0;
            for (int j = 0; j < 11; ++j) {
                index <<= 1;
                if (concatBits[(i * 11) + j]) {
                    index |= 0x1;
                }
            }
            words.add(this.wordList.get(index));
        }

        return words;
    }

    /**
     * Check to see if a mnemonic word list is valid.
     */
    public void check(List<String> words) throws MnemonicException {
        toEntropy(words);
    }

    private static boolean[] bytesToBits(byte[] data) {
        boolean[] bits = new boolean[data.length * 8];
        for (int i = 0; i < data.length; ++i)
            for (int j = 0; j < 8; ++j)
                bits[(i * 8) + j] = (data[i] & (1 << (7 - j))) != 0;
        return bits;
    }

    public List<String> getPossibleLastWords(List<String> previousWords) throws MnemonicException.MnemonicLengthException, MnemonicException.MnemonicWordException {
        if((previousWords.size() + 1) % 3 > 0) {
            throw new MnemonicException.MnemonicLengthException("Previous word list size must be multiple of three words, less one.");
        }

        // Look up all the words in the list and construct the
        // concatenation of the original entropy and the checksum.
        //
        int concatLenBits = previousWords.size() * 11;
        boolean[] concatBits = new boolean[concatLenBits];
        int wordindex = 0;
        for (String word : previousWords) {
            // Find the words index in the wordlist.
            int ndx = Collections.binarySearch(this.wordList, word);
            if (ndx < 0) {
                throw new MnemonicException.MnemonicWordException(word);
            }
            // Set the next 11 bits to the value of the index.
            for (int ii = 0; ii < 11; ++ii) {
                concatBits[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0;
            }
            ++wordindex;
        }

        int checksumLengthBits = (concatLenBits + 11) / 33;
        int entropyLengthBits = (concatLenBits + 11) - checksumLengthBits;
        int varyingLengthBits = entropyLengthBits - concatLenBits;

        boolean[][] bitPermutations = getBitPermutations(varyingLengthBits);

        ArrayList<String> possibleWords = new ArrayList<>();
        for(boolean[] bitPermutation : bitPermutations) {
            boolean[] entropyBits = new boolean[concatLenBits + varyingLengthBits];
            System.arraycopy(concatBits, 0, entropyBits, 0, concatBits.length);
            System.arraycopy(bitPermutation, 0, entropyBits, concatBits.length, varyingLengthBits);

            byte[] entropy = new byte[entropyLengthBits / 8];
            for(int ii = 0; ii < entropy.length; ++ii) {
                for(int jj = 0; jj < 8; ++jj) {
                    if(entropyBits[(ii * 8) + jj]) {
                        entropy[ii] |= 1 << (7 - jj);
                    }
                }
            }

            byte[] hash = Sha256Hash.hash(entropy);
            boolean[] hashBits = bytesToBits(hash);

            boolean[] wordBits = new boolean[11];
            System.arraycopy(bitPermutation, 0, wordBits, 0, varyingLengthBits);
            System.arraycopy(hashBits, 0, wordBits, varyingLengthBits, checksumLengthBits);

            int index = 0;
            for(int j = 0; j < 11; ++j) {
                index <<= 1;
                if(wordBits[j]) {
                    index |= 0x1;
                }
            }

            possibleWords.add(this.wordList.get(index));
        }

        Collections.sort(possibleWords);

        return possibleWords;
    }

    public static boolean[][] getBitPermutations(int length) {
        int numPermutations = (int) Math.pow(2, length);
        boolean[][] permutations = new boolean[numPermutations][length];

        for (int i = 0; i < numPermutations; i++) {
            for (int j = 0; j < length; j++) {
                permutations[i][j] = ((i >> j) & 1) == 1;
            }
        }

        return permutations;
    }
}
