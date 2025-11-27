package com.sparrowwallet.drongo.wallet.bip93;

import com.sparrowwallet.drongo.protocol.Bech32;
import com.sparrowwallet.drongo.protocol.ProtocolException;
import com.sparrowwallet.drongo.wallet.MnemonicException;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Locale;

public class Codex32 {

    private static final String HRP = "ms";
    private static final char SPECIAL_SHARE_INDEX = 's';
    private static final int CODEX32_ID_LEN = 4;

    public static class Codex32Data {
        public final byte[] rawData;
        public final ChecksumType checksumType;

        public Codex32Data(byte[] rawData, ChecksumType checksumType) {
            this.rawData = rawData;
            this.checksumType = checksumType;
        }

        public byte getThreshold() {
            return rawData[0];
        }

        public int getThresholdAsInt() {
            return Bech32.CHARSET.charAt(getThreshold()) - '0';
        }

        public byte[] getIdentifier() {
            return Arrays.copyOfRange(rawData, 1, 5);
        }

        public String identifierAsString() {
            byte[] id = getIdentifier();

            StringBuilder sb = new StringBuilder(CODEX32_ID_LEN);
            for(byte b : id) {
                sb.append(Bech32.CHARSET.charAt(b));
            }
            return sb.toString();
        }

        public byte getShareIndex() {
            return rawData[5];
        }

        public boolean isUnsharedSecret() {
            return getShareIndex() == Bech32.CHARSET_REV[SPECIAL_SHARE_INDEX];
        }

        public byte[] getPayload() {
            return Arrays.copyOfRange(rawData, 6, rawData.length);
        }

        public byte[] payloadToBip32Secret() throws MnemonicException {
            if(!isUnsharedSecret()) {
                throw new MnemonicException("Trying to get secret from non-secret share");
            }
            byte[] payload = getPayload();
            return Bech32.convertBits(payload, 0, payload.length, 5, 8, false, false);
        }
    }

    public static String encode(Codex32Data data) throws MnemonicException {
        byte[] checksum = createChecksum(data.rawData, data.checksumType);

        StringBuilder sb = new StringBuilder();
        sb.append(Codex32.HRP);
        sb.append(Bech32.BECH32_SEPARATOR);
        for(byte b : data.rawData) {
            sb.append(Bech32.CHARSET.charAt(b));
        }
        for(byte b : checksum) {
            sb.append(Bech32.CHARSET.charAt(b));
        }
        String result =  sb.toString();
        validate(result, 2);
        return result;
    }

    public static Codex32Data decode(String str) throws MnemonicException {
        final int separatorPos = str.lastIndexOf(Bech32.BECH32_SEPARATOR);

        validate(str, separatorPos);

        byte[] rawData = Bech32.rawDecode(str, separatorPos);
        int dataLen = rawData.length;

        ChecksumType checksumType = verifyChecksum(rawData);

        byte[] dataPart = new byte[dataLen - checksumType.length];
        System.arraycopy(rawData, 0, dataPart, 0, dataLen - checksumType.length);

        return new Codex32Data(dataPart, checksumType);
    }

    public static void validate(String str, int separatorPos) throws MnemonicException {
        if(str.length() < 48 || str.length() > 127) {
            throw new MnemonicException("Input invalid length: " + str.length());
        }

        try {
            // Can set checksum len to zero, since we validate if string is too short above
            Bech32.validate(str, 127, separatorPos, 0);
        } catch(ProtocolException e) {
            throw new MnemonicException("Input is not valid Bech32 string: " + e.getMessage());
        }

        String hrp = str.substring(0, separatorPos).toLowerCase(Locale.ROOT);
        if(!HRP.equals(hrp)) {
            throw new MnemonicException("Input does not have Codex32 \"ms\" human-readable part: " + hrp);
        }

        if(str.charAt(3) == '0' && str.toLowerCase(Locale.ROOT).charAt(8) != SPECIAL_SHARE_INDEX) {
            throw new MnemonicException("Non zero threshold with unshared secret share: " + str.charAt(8));
        }

        int threshold = str.charAt(3) - '0';
        if(!((threshold == 0) || (2 <= threshold && threshold <= 9))) {
            throw new MnemonicException("Threshold not in range: " + threshold);
        }
    }

    private static ChecksumType verifyChecksum(final byte[] values) throws MnemonicException {
        int dataLen = values.length;

        ChecksumType checksumType;
        if(dataLen <= 92) {
            checksumType = ChecksumType.CODEX32;
        } else if(dataLen >= 96 && dataLen <= 124) {
            checksumType = ChecksumType.CODEX32_LONG;
        } else {
            throw new MnemonicException("Data part invalid length: " + dataLen);
        }

        int payloadLen = dataLen - 6 - checksumType.length;
        if((payloadLen * 5) % 8 > 4) {
            throw new MnemonicException("Payload invalid length, incomplete group greater than 4 bits");
        }
        boolean verified = checksumType.polymod(values).equals(checksumType.constant);
        if(!verified) {
            throw new MnemonicException("Invalid Checksum");
        }

        return checksumType;
    }

    private static byte[] createChecksum(final byte[] values, ChecksumType checksumType) {
        BigInteger polymodInt = checksumType.polymod(Arrays.copyOf(values, values.length + checksumType.length));
        polymodInt = polymodInt.xor(checksumType.constant);
        byte[] buffer = new byte[checksumType.length];
        for(int i = 0; i < checksumType.length; i++) {
            byte[] intermediate = polymodInt.shiftRight(5 * (checksumType.length - 1 - i)).toByteArray();
            buffer[i] = (byte) (intermediate[intermediate.length - 1] & (byte) 31);
        }
        return buffer;
    }

    public enum ChecksumType {
        CODEX32(new BigInteger("10ce0795c2fd1e62a", 16), 13) {
            @Override
            public BigInteger polymod(final byte[] values) {
                BigInteger gen0 = new BigInteger("19dc500ce73fde210", 16);
                BigInteger gen1 = new BigInteger("1bfae00def77fe529", 16);
                BigInteger gen2 = new BigInteger("1fbd920fffe7bee52", 16);
                BigInteger gen3 = new BigInteger("1739640bdeee3fdad", 16);
                BigInteger gen4 = new BigInteger("07729a039cfc75f5a", 16);

                BigInteger sixtyOnes = new BigInteger("0fffffffffffffff", 16);
                BigInteger residue = new BigInteger("23181b3", 16);

                for(byte v_i : values) {
                    BigInteger b = residue.shiftRight(60);
                    residue = residue.and(sixtyOnes).shiftLeft(5);
                    residue = residue.xor(BigInteger.valueOf(v_i));
                    if(b.shiftRight(0).and(BigInteger.ONE).equals(BigInteger.ONE)) residue = residue.xor(gen0);
                    if(b.shiftRight(1).and(BigInteger.ONE).equals(BigInteger.ONE)) residue = residue.xor(gen1);
                    if(b.shiftRight(2).and(BigInteger.ONE).equals(BigInteger.ONE)) residue = residue.xor(gen2);
                    if(b.shiftRight(3).and(BigInteger.ONE).equals(BigInteger.ONE)) residue = residue.xor(gen3);
                    if(b.shiftRight(4).and(BigInteger.ONE).equals(BigInteger.ONE)) residue = residue.xor(gen4);
                }
                return residue;
            }
        },
        CODEX32_LONG(new BigInteger("43381e570bf4798ab26", 16), 15) {
            public BigInteger polymod(final byte[] values) {
                BigInteger gen0 = new BigInteger("3d59d273535ea62d897", 16);
                BigInteger gen1 = new BigInteger("7a9becb6361c6c51507", 16);
                BigInteger gen2 = new BigInteger("543f9b7e6c38d8a2a0e", 16);
                BigInteger gen3 = new BigInteger("0c577eaeccf1990d13c", 16);
                BigInteger gen4 = new BigInteger("1887f74f8dc71b10651", 16);

                BigInteger seventyOnes = new BigInteger("3fffffffffffffffff", 16);
                BigInteger residue = new BigInteger("23181b3", 16);

                for(byte v_i : values) {
                    BigInteger b = residue.shiftRight(70);
                    residue = residue.and(seventyOnes).shiftLeft(5);
                    residue = residue.xor(BigInteger.valueOf(v_i));
                    if(b.shiftRight(0).and(BigInteger.ONE).equals(BigInteger.ONE)) residue = residue.xor(gen0);
                    if(b.shiftRight(1).and(BigInteger.ONE).equals(BigInteger.ONE)) residue = residue.xor(gen1);
                    if(b.shiftRight(2).and(BigInteger.ONE).equals(BigInteger.ONE)) residue = residue.xor(gen2);
                    if(b.shiftRight(3).and(BigInteger.ONE).equals(BigInteger.ONE)) residue = residue.xor(gen3);
                    if(b.shiftRight(4).and(BigInteger.ONE).equals(BigInteger.ONE)) residue = residue.xor(gen4);
                }
                return residue;
            }
        };

        public final BigInteger constant;
        public final int length;

        ChecksumType(BigInteger constant, int length) {
            this.constant = constant;
            this.length = length;
        }

        public BigInteger polymod(final byte[] values) {
            return BigInteger.ZERO;
        }
    }
}
