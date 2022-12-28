package com.sparrowwallet.drongo.protocol;

/*
 * Copyright 2018 Coinomi Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Locale;

public class Bech32 {
    /** The Bech32 character set for encoding. */
    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /** The Bech32 character set for decoding. */
    private static final byte[] CHARSET_REV = {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
            -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
            1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
            -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
            1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
    };

    public static class Bech32Data {
        public final String hrp;
        public final byte[] data;
        public final Encoding encoding;

        private Bech32Data(final String hrp, final byte[] data) {
            this.hrp = hrp;
            this.data = data;
            this.encoding = (data[0] == 0x00 ? Encoding.BECH32 : Encoding.BECH32M);
        }

        public Bech32Data(String hrp, byte[] data, Encoding encoding) {
            this.hrp = hrp;
            this.data = data;
            this.encoding = encoding;
        }
    }

    /** Find the polynomial with value coefficients mod the generator as 30-bit. */
    private static int polymod(final byte[] values) {
        int c = 1;
        for (byte v_i: values) {
            int c0 = (c >>> 25) & 0xff;
            c = ((c & 0x1ffffff) << 5) ^ (v_i & 0xff);
            if ((c0 &  1) != 0) c ^= 0x3b6a57b2;
            if ((c0 &  2) != 0) c ^= 0x26508e6d;
            if ((c0 &  4) != 0) c ^= 0x1ea119fa;
            if ((c0 &  8) != 0) c ^= 0x3d4233dd;
            if ((c0 & 16) != 0) c ^= 0x2a1462b3;
        }
        return c;
    }

    /** Expand a HRP for use in checksum computation. */
    private static byte[] expandHrp(final String hrp) {
        int hrpLength = hrp.length();
        byte[] ret = new byte[hrpLength * 2 + 1];
        for (int i = 0; i < hrpLength; ++i) {
            int c = hrp.charAt(i) & 0x7f; // Limit to standard 7-bit ASCII
            ret[i] = (byte) ((c >>> 5) & 0x07);
            ret[i + hrpLength + 1] = (byte) (c & 0x1f);
        }
        ret[hrpLength] = 0;
        return ret;
    }

    /** Verify a checksum. */
    private static Encoding verifyChecksum(final String hrp, final byte[] values) {
        byte[] hrpExpanded = expandHrp(hrp);
        byte[] combined = new byte[hrpExpanded.length + values.length];
        System.arraycopy(hrpExpanded, 0, combined, 0, hrpExpanded.length);
        System.arraycopy(values, 0, combined, hrpExpanded.length, values.length);

        int check = polymod(combined);
        for(Encoding encoding : Encoding.values()) {
            if(check == encoding.checksumConstant) {
                return encoding;
            }
        }

        return null;
    }

    /** Create a checksum. */
    private static byte[] createChecksum(final String hrp, Encoding encoding, final byte[] values)  {
        byte[] hrpExpanded = expandHrp(hrp);
        byte[] enc = new byte[hrpExpanded.length + values.length + 6];
        System.arraycopy(hrpExpanded, 0, enc, 0, hrpExpanded.length);
        System.arraycopy(values, 0, enc, hrpExpanded.length, values.length);
        int mod = polymod(enc) ^ encoding.checksumConstant;
        byte[] ret = new byte[6];
        for (int i = 0; i < 6; ++i) {
            ret[i] = (byte) ((mod >>> (5 * (5 - i))) & 31);
        }
        return ret;
    }

    /** Encode a Bech32 string. */
    public static String encode(final Bech32Data bech32) {
        return encode(bech32.hrp, bech32.encoding, bech32.data);
    }

    /** Encode a Bech32 string. */
    public static String encode(String hrp, int version, final byte[] values) {
        Encoding encoding = (version == 0 ? Encoding.BECH32 : Encoding.BECH32M);
        return encode(hrp, encoding, encode(version, values));
    }

        /** Encode a Bech32 string. */
    public static String encode(String hrp, Encoding encoding, final byte[] values) {
        if(hrp.length() < 1) {
            throw new ProtocolException("Human-readable part is too short");
        }

        if(hrp.length() > 83) {
            throw new ProtocolException("Human-readable part is too long");
        }

        hrp = hrp.toLowerCase(Locale.ROOT);
        byte[] checksum = createChecksum(hrp, encoding, values);
        byte[] combined = new byte[values.length + checksum.length];
        System.arraycopy(values, 0, combined, 0, values.length);
        System.arraycopy(checksum, 0, combined, values.length, checksum.length);
        StringBuilder sb = new StringBuilder(hrp.length() + 1 + combined.length);
        sb.append(hrp);
        sb.append('1');
        for (byte b : combined) {
            sb.append(CHARSET.charAt(b));
        }
        return sb.toString();
    }

    /** Decode a Bech32 string. */
    public static Bech32Data decode(final String str) {
        return decode(str, 90);
    }

    public static Bech32Data decode(final String str, int limit) {
        boolean lower = false, upper = false;
        if (str.length() < 8)
            throw new ProtocolException("Input too short: " + str.length());
        if (str.length() > limit)
            throw new ProtocolException("Input too long: " + str.length());
        for (int i = 0; i < str.length(); ++i) {
            char c = str.charAt(i);
            if (c < 33 || c > 126) throw new ProtocolException("Invalid character " + c + " at position " + i);
            if (c >= 'a' && c <= 'z') {
                if (upper)
                    throw new ProtocolException("Invalid character " + c + " at position " + i);
                lower = true;
            }
            if (c >= 'A' && c <= 'Z') {
                if (lower)
                    throw new ProtocolException("Invalid character " + c + " at position " + i);
                upper = true;
            }
        }
        final int pos = str.lastIndexOf('1');
        if (pos < 1) throw new ProtocolException("Missing human-readable part");
        final int dataPartLength = str.length() - 1 - pos;
        if (dataPartLength < 6) throw new ProtocolException("Data part too short: " + dataPartLength);
        byte[] values = new byte[dataPartLength];
        for (int i = 0; i < dataPartLength; ++i) {
            char c = str.charAt(i + pos + 1);
            if (CHARSET_REV[c] == -1) throw new ProtocolException("Invalid character " + c + " at position " + i);
            values[i] = CHARSET_REV[c];
        }
        String hrp = str.substring(0, pos).toLowerCase(Locale.ROOT);
        Encoding encoding = verifyChecksum(hrp, values);
        if(encoding == null) {
            throw new ProtocolException("Invalid checksum");
        }

        return new Bech32Data(hrp, Arrays.copyOfRange(values, 0, values.length - 6), encoding);
    }

    private static byte[] encode(int witnessVersion, byte[] witnessProgram) {
        byte[] convertedProgram = convertBits(witnessProgram, 0, witnessProgram.length, 8, 5, true);
        byte[] bytes = new byte[1 + convertedProgram.length];
        bytes[0] = (byte)(witnessVersion & 0xff);
        System.arraycopy(convertedProgram, 0, bytes, 1, convertedProgram.length);
        return bytes;
    }

    /**
     * Helper for re-arranging bits into groups.
     */
    public static byte[] convertBits(final byte[] in, final int inStart, final int inLen, final int fromBits,
                                      final int toBits, final boolean pad) {
        int acc = 0;
        int bits = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        final int maxv = (1 << toBits) - 1;
        final int max_acc = (1 << (fromBits + toBits - 1)) - 1;
        for (int i = 0; i < inLen; i++) {
            int value = in[i + inStart] & 0xff;
            if ((value >>> fromBits) != 0) {
                throw new ProtocolException(
                        String.format("Input value '%X' exceeds '%d' bit size", value, fromBits));
            }
            acc = ((acc << fromBits) | value) & max_acc;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                out.write((acc >>> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0)
                out.write((acc << (toBits - bits)) & maxv);
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
            throw new ProtocolException("Could not convert bits, invalid padding");
        }
        return out.toByteArray();
    }

    public enum Encoding {
        BECH32(1), BECH32M(0x2bc830a3);

        private final int checksumConstant;

        Encoding(int checksumConstant) {
            this.checksumConstant = checksumConstant;
        }
    }
}
