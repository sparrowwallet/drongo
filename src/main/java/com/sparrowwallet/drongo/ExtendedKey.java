package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.crypto.*;
import com.sparrowwallet.drongo.protocol.Base58;
import com.sparrowwallet.drongo.protocol.ScriptType;

import java.nio.ByteBuffer;
import java.util.*;

public class ExtendedKey {
    private final byte[] parentFingerprint;
    private final DeterministicKey key;
    private final ChildNumber keyChildNumber;
    private final DeterministicHierarchy hierarchy;

    public ExtendedKey(DeterministicKey key, byte[] parentFingerprint, ChildNumber keyChildNumber) {
        this.parentFingerprint = parentFingerprint;
        this.key = key;
        this.keyChildNumber = keyChildNumber;
        this.hierarchy = new DeterministicHierarchy(key);
    }

    public byte[] getParentFingerprint() {
        return parentFingerprint;
    }

    public DeterministicKey getKey() {
        return key;
    }

    public DeterministicKey getKey(List<ChildNumber> path) {
        return hierarchy.get(path);
    }

    public String toString() {
        return getExtendedKey();
    }

    public String toString(Header extendedKeyHeader) {
        return getExtendedKey(extendedKeyHeader);
    }

    public String getExtendedKey() {
        return Base58.encodeChecked(getExtendedKeyBytes());
    }

    public String getExtendedKey(Header extendedKeyHeader) {
        return Base58.encodeChecked(getExtendedKeyBytes(extendedKeyHeader));
    }

    public ChildNumber getKeyChildNumber() {
        return keyChildNumber;
    }

    public byte[] getExtendedKeyBytes() {
        return getExtendedKeyBytes(key.isPubKeyOnly() ? Header.xpub : Header.xprv);
    }

    public byte[] getExtendedKeyBytes(Header extendedKeyHeader) {
        ByteBuffer buffer = ByteBuffer.allocate(78);
        buffer.putInt(extendedKeyHeader.header);
        buffer.put((byte) key.getDepth());
        buffer.put(parentFingerprint);
        buffer.putInt(keyChildNumber.i());
        buffer.put(key.getChainCode());
        if(key.isPubKeyOnly()) {
            buffer.put(key.getPubKey());
        } else {
            buffer.put((byte)0);
            buffer.put(key.getPrivKeyBytes());
        }

        return buffer.array();
    }

    public static ExtendedKey fromDescriptor(String extPubKey) {
        byte[] serializedKey = Base58.decodeChecked(extPubKey);
        ByteBuffer buffer = ByteBuffer.wrap(serializedKey);
        int header = buffer.getInt();
        if(!Header.isValidHeader(header)) {
            throw new IllegalArgumentException("Unknown header bytes: " + DeterministicKey.toBase58(serializedKey).substring(0, 4));
        }

        int depth = buffer.get() & 0xFF; // convert signed byte to positive int since depth cannot be negative
        byte[] parentFingerprint = new byte[4];
        buffer.get(parentFingerprint);
        final int i = buffer.getInt();
        ChildNumber childNumber;
        List<ChildNumber> path;

        if(depth == 0) {
            //Poorly formatted extended key, add first child path element
            childNumber = new ChildNumber(0, false);
        } else if ((i & ChildNumber.HARDENED_BIT) != 0) {
            childNumber = new ChildNumber(i ^ ChildNumber.HARDENED_BIT, true); //already hardened
        } else {
            childNumber = new ChildNumber(i, false);
        }
        path = List.of(childNumber);

        byte[] chainCode = new byte[32];
        buffer.get(chainCode);
        byte[] data = new byte[33];
        buffer.get(data);
        if(buffer.hasRemaining()) {
            throw new IllegalArgumentException("Found unexpected data in key");
        }

        DeterministicKey pubKey = new DeterministicKey(path, chainCode, new LazyECPoint(ECKey.CURVE.getCurve(), data), depth, parentFingerprint);
        return new ExtendedKey(pubKey, parentFingerprint, childNumber);
    }

    public static boolean isValid(String extPubKey) {
        try {
            ExtendedKey.fromDescriptor(extPubKey);
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public ExtendedKey copy() {
        //DeterministicKey is effectively final
        return new ExtendedKey(key, Arrays.copyOf(parentFingerprint, parentFingerprint.length), keyChildNumber);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExtendedKey that = (ExtendedKey) o;
        return that.toString().equals(this.toString());
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    public enum Header {
        xprv("xprv", 0x0488ADE4, ScriptType.P2PKH),
        xpub("xpub", 0x0488B21E, ScriptType.P2PKH),
        yprv("yprv", 0x049D7878, ScriptType.P2SH_P2WPKH),
        ypub("ypub", 0x049D7CB2, ScriptType.P2SH_P2WPKH),
        zprv("zprv", 0x04b2430c, ScriptType.P2WPKH),
        zpub("zpub", 0x04B24746, ScriptType.P2WPKH),
        Yprv("Yprv", 0x0295b005, ScriptType.P2SH_P2WSH),
        Ypub("Ypub", 0x0295b43f, ScriptType.P2SH_P2WSH),
        Zprv("Zprv", 0x02aa7a99, ScriptType.P2WSH),
        Zpub("Zpub", 0x02aa7ed3, ScriptType.P2WSH),
        tpub("tpub", 0x043587cf, ScriptType.P2PKH),
        tprv("tprv", 0x04358394, ScriptType.P2PKH),
        uprv("uprv", 0x044a4e28, ScriptType.P2SH_P2WPKH),
        upub("upub", 0x044a5262, ScriptType.P2SH_P2WPKH),
        vprv("vprv", 0x045f18bc, ScriptType.P2WPKH),
        vpub("vpub", 0x045f1cf6, ScriptType.P2WPKH),
        Uprv("Uprv", 0x024285b5, ScriptType.P2SH_P2WSH),
        Upub("Upub", 0x024289ef, ScriptType.P2SH_P2WSH),
        Vprv("Vprv", 0x02575048, ScriptType.P2WSH),
        Vpub("Vpub", 0x02575483, ScriptType.P2WSH);

        private final String name;
        private final int header;
        private final ScriptType defaultScriptType;

        Header(String name, int header, ScriptType defaultScriptType) {
            this.name = name;
            this.header = header;
            this.defaultScriptType = defaultScriptType;
        }

        public String getName() {
            return name;
        }

        public int getHeader() {
            return header;
        }

        public ScriptType getDefaultScriptType() {
            return defaultScriptType;
        }

        public static Header fromExtendedKey(String xkey) {
            for(Header extendedKeyHeader : Header.values()) {
                if(xkey.startsWith(extendedKeyHeader.name)) {
                    return extendedKeyHeader;
                }
            }

            throw new IllegalArgumentException("Unrecognised extended key header for extended key: " + xpub);
        }

        public static Header fromScriptType(ScriptType scriptType, boolean privateKey) {
            for(Header header : Header.values()) {
                if(header.defaultScriptType != null && header.defaultScriptType.equals(scriptType) && header.isPrivate() == privateKey) {
                    return header;
                }
            }

            return Header.xpub;
        }

        private boolean isPrivate() {
            return name.endsWith("prv");
        }

        public static boolean isValidHeader(int header) {
            for(Header extendedKeyHeader : Header.values()) {
                if(header == extendedKeyHeader.header) {
                    return true;
                }
            }

            return false;
        }
    }
}