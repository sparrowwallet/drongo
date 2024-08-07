package com.sparrowwallet.drongo.wallet.slip39;

import com.sparrowwallet.drongo.wallet.MnemonicException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

import static com.sparrowwallet.drongo.wallet.slip39.Share.*;
import static com.sparrowwallet.drongo.wallet.slip39.Utils.*;

public class Shamir {
    private static final Table TABLE = precomputeExpLog();
    private static final Random RANDOM = new SecureRandom();

    private static Table precomputeExpLog() {
        int[] exp = new int[255];
        int[] log = new int[256];

        int poly = 1;
        for (int i = 0; i < 255; i++) {
            exp[i] = poly;
            log[poly] = i;

            // Multiply poly by the polynomial x + 1.
            poly = (poly << 1) ^ poly;

            // Reduce poly by x^8 + x^4 + x^3 + x + 1.
            if ((poly & 0x100) != 0) {
                poly ^= 0x11B;
            }
        }

        return new Table(exp, log);
    }

    public static byte[] interpolate(List<RawShare> shares, int x) throws MnemonicException {
        Set<Integer> xCoordinates = new HashSet<>();
        for(RawShare share : shares) {
            xCoordinates.add(share.index());
        }

        if(xCoordinates.size() != shares.size()) {
            throw new MnemonicException("Duplicate share", "Invalid set of shares, share indices must be unique");
        }

        Set<Integer> shareValueLengths = new HashSet<>();
        for(RawShare share : shares) {
            shareValueLengths.add(share.value().length);
        }

        if(shareValueLengths.size() != 1) {
            throw new MnemonicException("Mismatched length", "Invalid set of shares, all share values must have the same length");
        }

        if(xCoordinates.contains(x)) {
            for(RawShare share : shares) {
                if(share.index() == x) {
                    return share.value();
                }
            }
        }

        int logProd = 0;
        for(RawShare share : shares) {
            logProd += TABLE.log[share.index() ^ x];
        }

        byte[] result = new byte[shareValueLengths.iterator().next()];
        for(RawShare share : shares) {
            int logBasisEval = Math.floorMod(logProd - TABLE.log[share.index() ^ x] - shares.stream().mapToInt(s -> TABLE.log[share.index() ^ s.index()]).sum(), 255);

            byte[] shareData = share.value();
            for(int i = 0; i < result.length; i++) {
                int shareVal = Byte.toUnsignedInt(shareData[i]);
                int intermediateSum = Byte.toUnsignedInt(result[i]);
                result[i] = (byte) (intermediateSum ^ (shareVal != 0 ? TABLE.exp[(TABLE.log[shareVal] + logBasisEval) % 255] : 0));
            }
        }

        return result;
    }

    public static byte[] createDigest(byte[] randomData, byte[] sharedSecret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(randomData, "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] fullDigest = mac.doFinal(sharedSecret);
            return Arrays.copyOfRange(fullDigest, 0, DIGEST_LENGTH_BYTES);
        } catch(NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Error creating digest", e);
        }
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    public static List<RawShare> splitSecret(int threshold, int shareCount, byte[] sharedSecret) throws MnemonicException {
        if(threshold < 1) {
            throw new IllegalArgumentException("The requested threshold must be a positive integer.");
        }

        if(threshold > shareCount) {
            throw new IllegalArgumentException("The requested threshold must not exceed the number of shares.");
        }

        if(shareCount > MAX_SHARE_COUNT) {
            throw new IllegalArgumentException("The requested number of shares must not exceed " + MAX_SHARE_COUNT + ".");
        }

        List<RawShare> shares = new ArrayList<>();

        // If the threshold is 1, then the digest of the shared secret is not used.
        if(threshold == 1) {
            for(int i = 0; i < shareCount; i++) {
                shares.add(new RawShare(i, sharedSecret));
            }
            return shares;
        }

        int randomShareCount = threshold - 2;

        for(int i = 0; i < randomShareCount; i++) {
            shares.add(new RawShare(i, randomBytes(sharedSecret.length)));
        }

        byte[] randomPart = randomBytes(sharedSecret.length - DIGEST_LENGTH_BYTES);
        byte[] digest = createDigest(randomPart, sharedSecret);

        List<RawShare> baseShares = new ArrayList<>(shares);
        baseShares.add(new RawShare(DIGEST_INDEX, concatenate(digest, randomPart)));
        baseShares.add(new RawShare(SECRET_INDEX, sharedSecret));

        for(int i = randomShareCount; i < shareCount; i++) {
            shares.add(new RawShare(i, interpolate(baseShares, i)));
        }

        return shares;
    }

    public static byte[] recoverSecret(int threshold, List<RawShare> shares) throws MnemonicException {
        // If the threshold is 1, then the digest of the shared secret is not used.
        if(threshold == 1) {
            return shares.iterator().next().value();
        }

        byte[] sharedSecret = interpolate(shares, SECRET_INDEX);
        byte[] digestShare = interpolate(shares, DIGEST_INDEX);
        byte[] digest = new byte[DIGEST_LENGTH_BYTES];
        byte[] randomPart = new byte[digestShare.length - DIGEST_LENGTH_BYTES];

        System.arraycopy(digestShare, 0, digest, 0, DIGEST_LENGTH_BYTES);
        System.arraycopy(digestShare, DIGEST_LENGTH_BYTES, randomPart, 0, digestShare.length - DIGEST_LENGTH_BYTES);

        if(!MessageDigest.isEqual(digest, createDigest(randomPart, sharedSecret))) {
            throw new MnemonicException("Invalid digest", "Invalid digest of the shared secret");
        }

        return sharedSecret;
    }

    public static Map<Integer, ShareGroup> decodeMnemonics(Iterable<String> mnemonics) throws MnemonicException {
        Set<Share.CommonParameters> commonParams = new HashSet<>();
        Map<Integer, ShareGroup> groups = new HashMap<>();

        for(String mnemonic : mnemonics) {
            Share share = Share.fromMnemonic(mnemonic);
            commonParams.add(share.getCommonParameters());
            groups.computeIfAbsent(share.getGroupIndex(), k -> new ShareGroup()).add(share);
        }

        if(commonParams.size() != 1) {
            throw new MnemonicException("Mismatched parameters", "Invalid set of mnemonics, all mnemonics must begin with the same " + ID_EXP_LENGTH_WORDS + " words, "
                            + "must have the same group threshold and the same group count");
        }

        return groups;
    }

    public static List<List<Share>> splitEms(int groupThreshold, List<GroupParams> groups, EncryptedMasterSecret encryptedMasterSecret) throws MnemonicException {
        if(encryptedMasterSecret.getCiphertext().length * 8 < MIN_STRENGTH_BITS) {
            throw new IllegalArgumentException("The length of the master secret must be at least " + bitsToBytes(MIN_STRENGTH_BITS) + " bytes.");
        }

        if(groupThreshold > groups.size()) {
            throw new IllegalArgumentException("The requested group threshold must not exceed the number of groups.");
        }

        for(GroupParams group : groups) {
            if(group.threshold() == 1 && group.size() > 1) {
                throw new IllegalArgumentException("Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead.");
            }
        }

        List<RawShare> groupShares = splitSecret(groupThreshold, groups.size(), encryptedMasterSecret.getCiphertext());

        List<List<Share>> mnemonicShares = new ArrayList<>();
        for(int i = 0; i < groups.size(); i++) {
            GroupParams groupParams = groups.get(i);
            RawShare groupSecretShare = groupShares.get(i);
            List<Share> groupMnemonics = new ArrayList<>();
            List<RawShare> memberShares = splitSecret(groupParams.threshold(), groupParams.size(), groupSecretShare.value());

            for(int k = 0; k < memberShares.size(); k++) {
                RawShare memberShare = memberShares.get(k);
                Share share = new Share(
                        encryptedMasterSecret.getIdentifier(),
                        encryptedMasterSecret.isExtendable(),
                        encryptedMasterSecret.getIterationExponent(),
                        i, // group index
                        groupThreshold,
                        groups.size(),
                        k, // member index
                        groupParams.threshold(),
                        memberShare.value()
                );
                groupMnemonics.add(share);
            }

            mnemonicShares.add(groupMnemonics);
        }

        return mnemonicShares;
    }

    public static int randomIdentifier() {
        byte[] randomBytes = randomBytes(bitsToBytes(ID_LENGTH_BITS));
        int identifier = byteArrayToInt(randomBytes);
        return identifier & ((1 << ID_LENGTH_BITS) - 1);
    }

    public static List<List<String>> generateMnemonics(int groupThreshold, List<GroupParams> groups, byte[] masterSecret, byte[] passphrase, boolean extendable, int iterationExponent) throws MnemonicException {
        // Validate passphrase
        for(byte c : passphrase) {
            if(c < ASCII_MIN || c > ASCII_MAX) {
                throw new IllegalArgumentException("The passphrase must contain only printable ASCII characters (code points 32-126).");
            }
        }

        // Generate random identifier
        int identifier = randomIdentifier();

        // Encrypt master secret
        EncryptedMasterSecret encryptedMasterSecret = EncryptedMasterSecret.fromMasterSecret(masterSecret, passphrase, identifier, extendable, iterationExponent);

        // Split encrypted master secret into mnemonic shares
        List<List<Share>> groupedShares = splitEms(groupThreshold, groups, encryptedMasterSecret);

        // Convert shares to mnemonics
        List<List<String>> mnemonics = new ArrayList<>();
        for(List<Share> group : groupedShares) {
            List<String> groupMnemonics = new ArrayList<>();
            for(Share share : group) {
                groupMnemonics.add(share.getMnemonic());
            }
            mnemonics.add(groupMnemonics);
        }

        return mnemonics;
    }

    public static EncryptedMasterSecret recoverEms(Map<Integer, ShareGroup> groups) throws MnemonicException {
        // Check if groups is empty
        if(groups.isEmpty()) {
            throw new MnemonicException("No shares", "The set of shares is empty");
        }

        // Get common parameters from the first group
        Share.CommonParameters params = groups.values().iterator().next().getCommonParameters();

        // Check if the number of groups meets the required threshold
        if(groups.size() < params.groupThreshold()) {
            throw new MnemonicException("Insufficient groups", String.format("Insufficient number of mnemonic groups, the required number of groups is %d", params.groupThreshold()));
        }

        // Check if the number of groups matches the required threshold
        if(groups.size() != params.groupThreshold()) {
            throw new MnemonicException("Too many groups", String.format("Wrong number of mnemonic groups, expected %d groups, but %d were provided", params.groupThreshold(), groups.size()));
        }

        // Validate each group has the correct number of shares
        for(Map.Entry<Integer, ShareGroup> entry : groups.entrySet()) {
            ShareGroup group = entry.getValue();
            if(group.size() != group.getMemberThreshold()) {
                String prefix = String.join(" ", group.iterator().next().getWords().subList(0, GROUP_PREFIX_LENGTH_WORDS));
                throw new MnemonicException("Group shares mismatch", String.format("Wrong number of mnemonics, expected %d mnemonics starting with \"%s ...\", but %d were provided", group.getMemberThreshold(), prefix, group.size()));
            }
        }

        // Recover shares from groups
        List<RawShare> groupShares = new ArrayList<>();
        for(Map.Entry<Integer, ShareGroup> entry : groups.entrySet()) {
            groupShares.add(new RawShare(entry.getKey(), recoverSecret(entry.getValue().getMemberThreshold(), entry.getValue().toRawShares())));
        }

        // Recover the encrypted master secret
        byte[] ciphertext = recoverSecret(params.groupThreshold(), groupShares);
        return new EncryptedMasterSecret(params.identifier(), params.extendable(), params.iterationExponent(), ciphertext);
    }

    public static byte[] combineMnemonics(Iterable<String> mnemonics, byte[] passphrase) throws MnemonicException {
        if(!mnemonics.iterator().hasNext()) {
            throw new MnemonicException("No shares", "The list of mnemonics is empty");
        }

        Map<Integer, ShareGroup> groups = decodeMnemonics(mnemonics);
        EncryptedMasterSecret encryptedMasterSecret = recoverEms(groups);
        return encryptedMasterSecret.decrypt(passphrase);
    }

    private record Table(int[] exp, int[] log) {}
}
