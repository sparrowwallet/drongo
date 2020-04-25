package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.crypto.*;
import com.sparrowwallet.drongo.protocol.Base58;
import com.sparrowwallet.drongo.protocol.ScriptType;

import java.nio.ByteBuffer;
import java.util.*;

import static com.sparrowwallet.drongo.KeyDerivation.parsePath;

public class ExtendedPublicKey {
    private final byte[] parentFingerprint;
    private final DeterministicKey pubKey;
    private final ChildNumber pubKeyChildNumber;
    private final DeterministicHierarchy hierarchy;

    public ExtendedPublicKey(DeterministicKey pubKey, byte[] parentFingerprint, ChildNumber pubKeyChildNumber) {
        this.parentFingerprint = parentFingerprint;
        this.pubKey = pubKey;
        this.pubKeyChildNumber = pubKeyChildNumber;
        this.hierarchy = new DeterministicHierarchy(pubKey);
    }

    public byte[] getParentFingerprint() {
        return parentFingerprint;
    }

    public DeterministicKey getPubKey() {
        return pubKey;
    }

    public DeterministicKey getKey(List<ChildNumber> path) {
        return hierarchy.get(path);
    }

    public String toString() {
        return getExtendedPublicKey();
    }

    public String toString(XpubHeader xpubHeader) {
        return getExtendedPublicKey(xpubHeader);
    }

    public String getExtendedPublicKey() {
        return Base58.encodeChecked(getExtendedPublicKeyBytes());
    }

    public String getExtendedPublicKey(XpubHeader xpubHeader) {
        return Base58.encodeChecked(getExtendedPublicKeyBytes(xpubHeader));
    }

    public ChildNumber getPubKeyChildNumber() {
        return pubKeyChildNumber;
    }

    public byte[] getExtendedPublicKeyBytes() {
        return getExtendedPublicKeyBytes(XpubHeader.xpub);
    }

    public byte[] getExtendedPublicKeyBytes(XpubHeader xpubHeader) {
        ByteBuffer buffer = ByteBuffer.allocate(78);
        buffer.putInt(xpubHeader.header);
        buffer.put((byte)pubKey.getDepth());
        buffer.put(parentFingerprint);
        buffer.putInt(pubKeyChildNumber.i());
        buffer.put(pubKey.getChainCode());
        buffer.put(pubKey.getPubKey());

        return buffer.array();
    }

    public static ExtendedPublicKey fromDescriptor(String extPubKey) {
        byte[] serializedKey = Base58.decodeChecked(extPubKey);
        ByteBuffer buffer = ByteBuffer.wrap(serializedKey);
        int header = buffer.getInt();
        if(!XpubHeader.isValidHeader(header)) {
            throw new IllegalArgumentException("Unknown header bytes: " + DeterministicKey.toBase58(serializedKey).substring(0, 4));
        }

        int depth = buffer.get() & 0xFF; // convert signed byte to positive int since depth cannot be negative
        byte[] parentFingerprint = new byte[4];
        buffer.get(parentFingerprint);
        final int i = buffer.getInt();
        ChildNumber childNumber;
        List<ChildNumber> path;

        if(depth == 0) {
            //Poorly formatted extended public key, add first child path element
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
        return new ExtendedPublicKey(pubKey, parentFingerprint, childNumber);
    }

    public static boolean isValid(String extPubKey) {
        try {
            ExtendedPublicKey.fromDescriptor(extPubKey);
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public ExtendedPublicKey copy() {
        //DeterministicKey is effectively final
        return new ExtendedPublicKey(pubKey, Arrays.copyOf(parentFingerprint, parentFingerprint.length), pubKeyChildNumber);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExtendedPublicKey that = (ExtendedPublicKey) o;
        return that.toString().equals(this.toString());
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    public enum XpubHeader {
        xpub("xpub", 0x0488B21E, ScriptType.P2PKH),
        ypub("ypub", 0x049D7CB2, ScriptType.P2SH_P2WPKH),
        zpub("zpub", 0x04B24746, ScriptType.P2WPKH),
        Ypub("Ypub", 0x0295b43f, ScriptType.P2SH_P2WSH),
        Zpub("Zpub", 0x02aa7ed3, ScriptType.P2WSH),
        tpub("tpub", 0x043587cf, ScriptType.P2PKH),
        upub("upub", 0x044a5262, ScriptType.P2SH_P2WPKH),
        vpub("vpub", 0x045f1cf6, ScriptType.P2WPKH),
        Upub("Upub", 0x024289ef, ScriptType.P2SH_P2WSH),
        Vpub("Vpub", 0x02575483, ScriptType.P2WSH);

        private final String name;
        private final int header;
        private final ScriptType defaultScriptType;

        XpubHeader(String name, int header, ScriptType defaultScriptType) {
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

        public static XpubHeader fromXpub(String xpub) {
            for(XpubHeader xpubHeader : XpubHeader.values()) {
                if(xpub.startsWith(xpubHeader.name)) {
                    return xpubHeader;
                }
            }

            throw new IllegalArgumentException("Unrecognised xpub header for xpub: " + xpub);
        }

        public static XpubHeader fromScriptType(ScriptType scriptType) {
            for(XpubHeader xpubHeader : XpubHeader.values()) {
                if(xpubHeader.defaultScriptType.equals(scriptType)) {
                    return xpubHeader;
                }
            }

            return XpubHeader.xpub;
        }

        public static boolean isValidHeader(int header) {
            for(XpubHeader xpubHeader : XpubHeader.values()) {
                if(header == xpubHeader.header) {
                    return true;
                }
            }

            return false;
        }
    }
}