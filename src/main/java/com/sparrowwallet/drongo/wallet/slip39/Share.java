package com.sparrowwallet.drongo.wallet.slip39;

import com.sparrowwallet.drongo.wallet.MnemonicException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import static com.sparrowwallet.drongo.wallet.slip39.Utils.*;

public class Share {
    private static final int RADIX = 1024;

    public static final int ID_LENGTH_BITS = 15;
    private static final int ITERATION_EXP_LENGTH_BITS = 4;
    private static final int EXTENDABLE_FLAG_LENGTH_BITS = 1;
    public static final int ID_EXP_LENGTH_WORDS = bitsToWords(ID_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS);
    public static final int GROUP_PREFIX_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 1;

    public static final int CHECKSUM_LENGTH_WORDS = 3;
    public static final int MIN_STRENGTH_BITS = 128;
    private static final int METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS;
    private static final int MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + bitsToWords(MIN_STRENGTH_BITS);
    public static final byte[] CUSTOMIZATION_STRING_ORIG = "shamir".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] CUSTOMIZATION_STRING_EXTENDABLE = "shamir_extendable".getBytes(StandardCharsets.US_ASCII);

    public static final int ROUND_COUNT = 4;
    public static final int BASE_ITERATION_COUNT = 10000;

    public static final int DIGEST_LENGTH_BYTES = 4;

    public static final int MAX_SHARE_COUNT = 16;
    public static final int DIGEST_INDEX = 254;
    public static final int SECRET_INDEX = 255;

    public static final int ASCII_MIN = 32;
    public static final int ASCII_MAX = 126;

    private final int identifier;
    private final boolean extendable;
    private final int iterationExponent;
    private final int groupIndex;
    private final int groupThreshold;
    private final int groupCount;
    private final int index;
    private final int memberThreshold;
    private final byte[] value;

    public Share(int identifier, boolean extendable, int iterationExponent, int groupIndex, int groupThreshold, int groupCount, int index, int memberThreshold, byte[] value) {
        this.identifier = identifier;
        this.extendable = extendable;
        this.iterationExponent = iterationExponent;
        this.groupIndex = groupIndex;
        this.groupThreshold = groupThreshold;
        this.groupCount = groupCount;
        this.index = index;
        this.memberThreshold = memberThreshold;
        this.value = value;
    }

    public CommonParameters getCommonParameters() {
        return new CommonParameters(identifier, extendable, iterationExponent, groupThreshold, groupCount);
    }

    public GroupParameters getGroupParameters() {
        return new GroupParameters(identifier, extendable, iterationExponent, groupIndex, groupThreshold, groupCount, memberThreshold);
    }

    public int getIndex() {
        return index;
    }

    public byte[] getValue() {
        return value;
    }

    public int getMemberThreshold() {
        return memberThreshold;
    }

    public int getGroupIndex() {
        return groupIndex;
    }

    private List<Integer> encodeIdExp() {
        int idExp = identifier << (ITERATION_EXP_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS);
        idExp += (extendable ? 1 : 0) << ITERATION_EXP_LENGTH_BITS;
        idExp += iterationExponent;
        return intToWordIndices(BigInteger.valueOf(idExp), ID_EXP_LENGTH_WORDS);
    }

    private List<Integer> encodeShareParams() {
        //each value is 4 bits, for 20 bits total
        int val = groupIndex;
        val <<= 4;
        val += groupThreshold - 1;
        val <<= 4;
        val += groupCount - 1;
        val <<= 4;
        val += index;
        val <<= 4;
        val += memberThreshold - 1;
        //group parameters are 2 words
        return intToWordIndices(BigInteger.valueOf(val), 2);
    }

    public List<String> getWords() {
        int valueWordCount = bitsToWords(value.length * 8);
        BigInteger valueInt = new BigInteger(1, value);
        List<Integer> valueData = intToWordIndices(valueInt, valueWordCount);

        List<Integer> shareData = new ArrayList<>(encodeIdExp());
        shareData.addAll(encodeShareParams());
        shareData.addAll(valueData);
        List<Integer> checksum = Rs1024.createChecksum(shareData, getCustomizationString(extendable));

        shareData.addAll(checksum);
        return Slip39MnemonicCode.INSTANCE.getWordsFromIndices(shareData);
    }

    public String getMnemonic() {
        StringJoiner joiner = new StringJoiner(" ");
        getWords().forEach(joiner::add);
        return joiner.toString();
    }

    public static Share fromMnemonic(List<String> mnemonic) throws MnemonicException {
        return fromMnemonic(String.join(" ", mnemonic));
    }

    public static Share fromMnemonic(String mnemonic) throws MnemonicException {
        List<Integer> mnemonicData = Slip39MnemonicCode.INSTANCE.getIndicesFromMnemonic(mnemonic);
        if(mnemonicData.size() < MIN_MNEMONIC_LENGTH_WORDS) {
            throw new MnemonicException("Too few words", "Invalid mnemonic length, the length of each mnemonic must be at least " + MIN_MNEMONIC_LENGTH_WORDS + " words");
        }

        int paddingLen = (RADIX_BITS * (mnemonicData.size() - METADATA_LENGTH_WORDS)) % 16;
        if(paddingLen > 8) {
            throw new MnemonicException("Invalid mnemonic", "Invalid mnemonic length, padding of " + paddingLen);
        }

        List<Integer> idExpData = mnemonicData.subList(0, ID_EXP_LENGTH_WORDS);
        int idExp = intFromWordIndices(idExpData).intValue();

        int identifier = idExp >> (EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS);
        boolean extendable = ((idExp >> ITERATION_EXP_LENGTH_BITS) & 1) > 0;
        int iterationExponent = idExp & ((1 << ITERATION_EXP_LENGTH_BITS) - 1);

        if(!Rs1024.verifyChecksum(mnemonicData, getCustomizationString(extendable))) {
            throw new MnemonicException("Invalid checksum", "Invalid mnemonic checksum for " + Arrays.stream(mnemonic.split(" ")).limit(ID_EXP_LENGTH_WORDS + 2).collect(Collectors.joining(" ")));
        }

        List<Integer> shareParamsData = mnemonicData.subList(ID_EXP_LENGTH_WORDS, ID_EXP_LENGTH_WORDS + 2);
        BigInteger shareParamsInt = intFromWordIndices(shareParamsData);
        List<Integer> shareParams = intToIndices(shareParamsInt, 5, 4);
        int groupIndex = shareParams.get(0);
        int groupThreshold = shareParams.get(1);
        int groupCount = shareParams.get(2);
        int index = shareParams.get(3);
        int memberThreshold = shareParams.get(4);

        if(groupCount < groupThreshold) {
            throw new MnemonicException("Invalid mnemonic", "Invalid mnemonic, group threshold cannot be greater than group count");
        }

        List<Integer> valueData = mnemonicData.subList(ID_EXP_LENGTH_WORDS + 2, mnemonicData.size() - CHECKSUM_LENGTH_WORDS);
        int valueByteCount = bitsToBytes(RADIX_BITS * valueData.size() - paddingLen);
        byte[] value = intFromWordIndices(valueData).toByteArray();
        if(value.length == valueByteCount + 1 && value[0] == 0) {
            value = Arrays.copyOfRange(value, 1, value.length);
        }

        if(value.length > valueByteCount) {
            throw new MnemonicException("Invalid mnemonic", "Invalid mnemonic padding");
        }

        return new Share(identifier, extendable, iterationExponent, groupIndex, groupThreshold + 1, groupCount + 1, index, memberThreshold + 1, value);
    }

    public static List<Integer> intToWordIndices(BigInteger value, int length) {
        return intToIndices(value, length, RADIX_BITS);
    }

    public static BigInteger intFromWordIndices(List<Integer> indices) {
        BigInteger value = BigInteger.valueOf(0);
        for(int index : indices) {
            value = value.multiply(BigInteger.valueOf(RADIX)).add(BigInteger.valueOf(index));
        }
        return value;
    }

    public static byte[] getCustomizationString(boolean extendable) {
        return extendable ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_ORIG;
    }

    public Share withGroupIndex(int groupIndex) {
        return new Share(identifier, extendable, iterationExponent, groupIndex, groupThreshold, groupCount, index, memberThreshold, value);
    }

    public record CommonParameters(int identifier, boolean extendable, int iterationExponent, int groupThreshold, int groupCount) {}
    public record GroupParameters(int identifier, boolean extendable, int iterationExponent, int groupIndex, int groupThreshold, int groupCount, int memberThreshold) {}
}


