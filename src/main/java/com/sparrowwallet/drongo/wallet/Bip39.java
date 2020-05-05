package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.*;

public class Bip39 {
    private Map<String, Integer> wordlistIndex;

    public byte[] getSeed(List<String> mnemonicWords, String passphrase) {
        loadWordlistIndex();

        int concatLength = mnemonicWords.size() * 11;
        StringBuilder concat = new StringBuilder();
        for(String mnemonicWord : mnemonicWords) {
            Integer index = wordlistIndex.get(mnemonicWord);
            if (index == null) {
                throw new IllegalArgumentException("Provided mnemonic word \"" + mnemonicWord + "\" is not in the BIP39 english word list");
            }

            String binaryIndex = addLeadingZeros(Integer.toBinaryString(index), 11);
            concat.append(binaryIndex, 0, 11);
        }

        int checksumLength = concatLength / 33;
        int entropyLength = concatLength - checksumLength;
        byte[] entropy = byteArrayFromBinaryString(concat.substring(0, entropyLength));
        String providedChecksum = concat.substring(entropyLength);

        byte[] sha256 = Sha256Hash.hash(entropy);
        String calculatedChecksum = addLeadingZeros(Integer.toBinaryString(Byte.toUnsignedInt(sha256[0])), 8).substring(0, checksumLength);

        if(!providedChecksum.equals(calculatedChecksum)) {
            throw new IllegalArgumentException("Provided mnemonic words do not represent a valid BIP39 seed: checksum failed");
        }

        String saltStr = "mnemonic";
        if(passphrase != null) {
            saltStr += Normalizer.normalize(passphrase, Normalizer.Form.NFKD);
        }
        byte[] salt = saltStr.getBytes(StandardCharsets.UTF_8);

        String mnemonic = String.join(" ", mnemonicWords);
        mnemonic = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD);

        return Utils.getPbkdf2HmacSha512Hash(mnemonic.getBytes(StandardCharsets.UTF_8), salt, 2048);
    }

    public String addLeadingZeros(String s, int length) {
        if (s.length() >= length) return s;
        else return String.format("%0" + (length-s.length()) + "d%s", 0, s);
    }

    private byte[] byteArrayFromBinaryString(String binaryString) {
        int splitSize = 8;

        if(binaryString.length() < splitSize) {
            binaryString = addLeadingZeros(binaryString, 8);
        }

        if(binaryString.length() % splitSize == 0){
            int index = 0;
            int position = 0;

            byte[] resultByteArray = new byte[binaryString.length()/splitSize];
            StringBuilder text = new StringBuilder(binaryString);

            while (index < text.length()) {
                String binaryStringChunk = text.substring(index, Math.min(index + splitSize, text.length()));
                int byteAsInt = Integer.parseInt(binaryStringChunk, 2);
                resultByteArray[position] = (byte)byteAsInt;
                index += splitSize;
                position ++;
            }
            return resultByteArray;
        }
        else {
            throw new IllegalArgumentException("Cannot convert binary string to byte[], because of the input length '" + binaryString + "' % 8 != 0");
        }
    }

    private void loadWordlistIndex() {
        if(wordlistIndex == null) {
            wordlistIndex = new HashMap<>();

            try{
                BufferedReader reader = new BufferedReader(new InputStreamReader(this.getClass().getResourceAsStream("/wordlist/bip39-english.txt"), StandardCharsets.UTF_8));
                String line;
                for(int i = 0; (line = reader.readLine()) != null; i++) {
                    wordlistIndex.put(line.trim(), i);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
