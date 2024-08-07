package com.sparrowwallet.drongo.wallet.slip39;

import com.sparrowwallet.drongo.wallet.MnemonicException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Slip39MnemonicCode {
    private static final Logger log = LoggerFactory.getLogger(Slip39MnemonicCode.class);
    public static final int MAX_ABBREVIATED_WORD_LENGTH = 4;

    private final ArrayList<String> wordList;
    private final Map<Integer, String> wordIndexMap;

    private static final String SLIP39_RESOURCE_NAME = "/wordlist/slip39.txt";

    static {
        try {
            INSTANCE = new Slip39MnemonicCode();
        } catch (RuntimeException e) {
            log.error("Failed to load word list", e);
        }
    }

    public static Slip39MnemonicCode INSTANCE;

    public Slip39MnemonicCode() {
        this(openDefaultWords());
    }

    private static InputStream openDefaultWords() {
        InputStream stream = Slip39MnemonicCode.class.getResourceAsStream(SLIP39_RESOURCE_NAME);
        if(stream == null) {
            throw new RuntimeException(new FileNotFoundException(SLIP39_RESOURCE_NAME));
        }

        return stream;
    }

    public Slip39MnemonicCode(InputStream wordstream) throws IllegalArgumentException {
        try(BufferedReader br = new BufferedReader(new InputStreamReader(wordstream, StandardCharsets.UTF_8))) {
            this.wordList = new ArrayList<>(1024);
            String word;
            while((word = br.readLine()) != null) {
                this.wordList.add(word);
            }

            if(this.wordList.size() != 1024) {
                throw new IllegalArgumentException("Input stream did not contain 2048 words");
            }

            this.wordIndexMap = new HashMap<>(1024);
            for(int i = 0; i < wordList.size(); i++) {
                this.wordIndexMap.put(i, wordList.get(i));
            }
        } catch (IOException e) {
            throw new RuntimeException("Error loading word list", e);
        }
    }

    public List<String> getWordList() {
        return Collections.unmodifiableList(wordList);
    }

    public List<String> getWordsFromIndices(List<Integer> indices) {
        return indices.stream().map(wordIndexMap::get).toList();
    }

    public String getMnemonicFromIndices(List<Integer> indices) {
        StringJoiner joiner = new StringJoiner(" ");
        getWordsFromIndices(indices).forEach(joiner::add);
        return joiner.toString();
    }

    public List<Integer> getIndicesFromMnemonic(String mnemonic) {
        String[] words = mnemonic.split(" ");
        return Arrays.stream(words).map(wordList::indexOf).toList();
    }

    public byte[] toSeed(List<String> mnemonicCode, String passphrase) throws MnemonicException {
        Share share = Share.fromMnemonic(mnemonicCode);
        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(share);
        return recoveryState.recover(getPassphraseBytes(passphrase));
    }

    public List<String> toSingleShareMnemonic(byte[] masterSecret, String passphrase) throws MnemonicException {
        byte[] passphraseBytes = getPassphraseBytes(passphrase);
        List<List<String>> groupShares = Shamir.generateMnemonics(1, List.of(new GroupParams(1, 1)), masterSecret, passphraseBytes, true, 1);
        List<String> firstGroup = groupShares.get(0);
        String firstShare = firstGroup.get(0);
        return Arrays.asList(firstShare.split(" "));
    }

    public static byte[] getPassphraseBytes(String passphrase) throws MnemonicException {
        byte[] passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);
        for(byte passphraseByte : passphraseBytes) {
            if(passphraseByte < 32 || passphraseByte > 126) {
                throw new MnemonicException("Unprintable passphrase character");
            }
        }

        return passphraseBytes;
    }

    public static String truncate(String word) {
        return word.length() > MAX_ABBREVIATED_WORD_LENGTH ? word.substring(0, MAX_ABBREVIATED_WORD_LENGTH) : word;
    }

    public static String lengthen(String abbreviation) {
        if(abbreviation.length() == MAX_ABBREVIATED_WORD_LENGTH) {
            for(String word : Slip39MnemonicCode.INSTANCE.getWordList()) {
                if(word.startsWith(abbreviation)) {
                    return word;
                }
            }
        }

        return abbreviation;
    }
}

