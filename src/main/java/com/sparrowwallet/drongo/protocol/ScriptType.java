package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.address.*;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.sparrowwallet.drongo.policy.PolicyType.*;
import static com.sparrowwallet.drongo.protocol.Script.decodeFromOpN;
import static com.sparrowwallet.drongo.protocol.ScriptOpCodes.*;

public enum ScriptType {
    P2PK("P2PK", new PolicyType[]{SINGLE}) {
        @Override
        public Address getAddress(byte[] pubKey) {
            return new P2PKAddress(pubKey);
        }

        @Override
        public Address[] getAddresses(Script script) {
            return new Address[] { getAddress(getPublicKeyFromScript(script).getPubKey()) };
        }

        @Override
        public Script getOutputScript(byte[] pubKey) {
            List<ScriptChunk> chunks = new ArrayList<>();
            chunks.add(new ScriptChunk(pubKey.length, pubKey));
            chunks.add(new ScriptChunk(ScriptOpCodes.OP_CHECKSIG, null));

            return new Script(chunks);
        }

        @Override
        public boolean isScriptType(Script script) {
            List<ScriptChunk> chunks = script.chunks;
            if (chunks.size() != 2)
                return false;
            if (!chunks.get(0).equalsOpCode(0x21) && !chunks.get(0).equalsOpCode(0x41))
                return false;
            byte[] chunk2data = chunks.get(0).data;
            if (chunk2data == null)
                return false;
            if (chunk2data.length != 33 && chunk2data.length != 65)
                return false;
            if (!chunks.get(1).equalsOpCode(OP_CHECKSIG))
                return false;
            return true;
        }

        @Override
        public byte[] getHashFromScript(Script script) {
            throw new ProtocolException("P2PK script does contain hash, use getPublicKeyFromScript(script) to retreive public key");
        }

        @Override
        public ECKey getPublicKeyFromScript(Script script) {
            return ECKey.fromPublicOnly(script.chunks.get(0).data);
        }
    },
    P2PKH("P2PKH", new PolicyType[]{SINGLE}) {
        @Override
        public Address getAddress(byte[] pubKeyHash) {
            return new P2PKHAddress(pubKeyHash);
        }

        @Override
        public Script getOutputScript(byte[] pubKeyHash) {
            List<ScriptChunk> chunks = new ArrayList<>();
            chunks.add(new ScriptChunk(ScriptOpCodes.OP_DUP, null));
            chunks.add(new ScriptChunk(ScriptOpCodes.OP_HASH160, null));
            chunks.add(new ScriptChunk(pubKeyHash.length, pubKeyHash));
            chunks.add(new ScriptChunk(ScriptOpCodes.OP_EQUALVERIFY, null));
            chunks.add(new ScriptChunk(ScriptOpCodes.OP_CHECKSIG, null));

            return new Script(chunks);
        }

        @Override
        public boolean isScriptType(Script script) {
            List<ScriptChunk> chunks = script.chunks;
            if (chunks.size() != 5)
                return false;
            if (!chunks.get(0).equalsOpCode(OP_DUP))
                return false;
            if (!chunks.get(1).equalsOpCode(OP_HASH160))
                return false;
            byte[] chunk2data = chunks.get(2).data;
            if (chunk2data == null)
                return false;
            if (chunk2data.length != 20)
                return false;
            if (!chunks.get(3).equalsOpCode(OP_EQUALVERIFY))
                return false;
            if (!chunks.get(4).equalsOpCode(OP_CHECKSIG))
                return false;
            return true;
        }

        @Override
        public byte[] getHashFromScript(Script script) {
            return script.chunks.get(2).data;
        }
    },
    MULTISIG("Bare Multisig", new PolicyType[]{MULTI}) {
        @Override
        public Address getAddress(byte[] bytes) {
            throw new ProtocolException("No single address for multisig script type");
        }

        @Override
        public Address[] getAddresses(Script script) {
            return Arrays.stream(getPublicKeysFromScript(script)).map(pubKey -> new P2PKAddress(pubKey.getPubKey())).toArray(Address[]::new);
        }

        @Override
        public Script getOutputScript(byte[] bytes) {
            throw new ProtocolException("Output script for multisig script type must be constructed with method getOutputScript(int threshold, byte[] pubKey1, byte[] pubKey2, ...)");
        }

        public Script getOutputScript(int threshold, byte[] ...pubKeys) {
            List<ScriptChunk> chunks = new ArrayList<>();
            chunks.add(new ScriptChunk(Script.encodeToOpN(threshold), null));
            for(byte[] pubKey : pubKeys) {
                chunks.add(new ScriptChunk(pubKey.length, pubKey));
            }
            chunks.add(new ScriptChunk(Script.encodeToOpN(pubKeys.length), null));
            chunks.add(new ScriptChunk(ScriptOpCodes.OP_CHECKMULTISIG, null));
            return new Script(chunks);
        }

        @Override
        public boolean isScriptType(Script script) {
            List<ScriptChunk> chunks = script.chunks;
            if (chunks.size() < 4) return false;
            ScriptChunk chunk = chunks.get(chunks.size() - 1);
            // Must end in OP_CHECKMULTISIG[VERIFY].
            if (!chunk.isOpCode()) return false;
            if (!(chunk.equalsOpCode(OP_CHECKMULTISIG) || chunk.equalsOpCode(OP_CHECKMULTISIGVERIFY))) return false;
            try {
                // Second to last chunk must be an OP_N opcode and there should be that many data chunks (keys).
                ScriptChunk m = chunks.get(chunks.size() - 2);
                if (!m.isOpCode()) return false;
                int numKeys = Script.decodeFromOpN(m.opcode);
                if (numKeys < 1 || chunks.size() != 3 + numKeys) return false;
                for (int i = 1; i < chunks.size() - 2; i++) {
                    if (chunks.get(i).isOpCode()) return false;
                }
                // First chunk must be an OP_N opcode too.
                if (Script.decodeFromOpN(chunks.get(0).opcode) < 1) return false;
            } catch (IllegalStateException e) {
                return false;   // Not an OP_N opcode.
            }
            return true;
        }

        @Override
        public byte[] getHashFromScript(Script script) {
            throw new ProtocolException("Public keys for bare multisig script type must be retrieved with method getPublicKeysFromScript(Script script)");
        }

        @Override
        public ECKey[] getPublicKeysFromScript(Script script) {
            List<ECKey> pubKeys = new ArrayList<>();

            List<ScriptChunk> chunks = script.chunks;
            for (int i = 1; i < chunks.size() - 2; i++) {
                byte[] pubKey = chunks.get(i).data;
                pubKeys.add(ECKey.fromPublicOnly(pubKey));
            }

            return pubKeys.toArray(new ECKey[pubKeys.size()]);
        }

        @Override
        public int getThreshold(Script script) {
            return decodeFromOpN(script.chunks.get(0).opcode);
        }
    },
    P2SH("P2SH", new PolicyType[]{MULTI}) {
        @Override
        public Address getAddress(byte[] bytes) {
            return new P2SHAddress(bytes);
        }

        @Override
        public Script getOutputScript(byte[] bytes) {
            List<ScriptChunk> chunks = new ArrayList<>();
            chunks.add(new ScriptChunk(ScriptOpCodes.OP_HASH160, null));
            chunks.add(new ScriptChunk(bytes.length, bytes));
            chunks.add(new ScriptChunk(ScriptOpCodes.OP_EQUAL, null));

            return new Script(chunks);
        }

        @Override
        public boolean isScriptType(Script script) {
            List<ScriptChunk> chunks = script.chunks;
            // We check for the effective serialized form because BIP16 defines a P2SH output using an exact byte
            // template, not the logical program structure. Thus you can have two programs that look identical when
            // printed out but one is a P2SH script and the other isn't! :(
            // We explicitly test that the op code used to load the 20 bytes is 0x14 and not something logically
            // equivalent like {@code OP_HASH160 OP_PUSHDATA1 0x14 <20 bytes of script hash> OP_EQUAL}
            if (chunks.size() != 3)
                return false;
            if (!chunks.get(0).equalsOpCode(OP_HASH160))
                return false;
            ScriptChunk chunk1 = chunks.get(1);
            if (chunk1.opcode != 0x14)
                return false;
            byte[] chunk1data = chunk1.data;
            if (chunk1data == null)
                return false;
            if (chunk1data.length != 20)
                return false;
            if (!chunks.get(2).equalsOpCode(OP_EQUAL))
                return false;
            return true;
        }

        @Override
        public byte[] getHashFromScript(Script script) {
            return script.chunks.get(1).data;
        }
    },
    P2SH_P2WPKH("P2SH-P2WPKH", new PolicyType[]{SINGLE}) {
        @Override
        public Address getAddress(byte[] bytes) {
            return P2SH.getAddress(bytes);
        }

        @Override
        public Script getOutputScript(byte[] bytes) {
            return P2SH.getOutputScript(bytes);
        }

        @Override
        public boolean isScriptType(Script script) {
            return P2SH.isScriptType(script);
        }

        @Override
        public byte[] getHashFromScript(Script script) {
            return P2SH.getHashFromScript(script);
        }
    },
    P2SH_P2WSH("P2SH-P2WSH", new PolicyType[]{MULTI, CUSTOM}) {
        @Override
        public Address getAddress(byte[] bytes) {
            return P2SH.getAddress(bytes);
        }

        @Override
        public Script getOutputScript(byte[] bytes) {
            return P2SH.getOutputScript(bytes);
        }

        @Override
        public boolean isScriptType(Script script) {
            return P2SH.isScriptType(script);
        }

        @Override
        public byte[] getHashFromScript(Script script) {
            return P2SH.getHashFromScript(script);
        }
    },
    P2WPKH("P2WPKH", new PolicyType[]{SINGLE}) {
        @Override
        public Address getAddress(byte[] bytes) {
            return new P2WPKHAddress(bytes);
        }

        @Override
        public Script getOutputScript(byte[] bytes) {
            List<ScriptChunk> chunks = new ArrayList<>();
            chunks.add(new ScriptChunk(OP_0, null));
            chunks.add(new ScriptChunk(bytes.length, bytes));

            return new Script(chunks);
        }

        @Override
        public boolean isScriptType(Script script) {
            List<ScriptChunk> chunks = script.chunks;
            if (chunks.size() != 2)
                return false;
            if (!chunks.get(0).equalsOpCode(OP_0))
                return false;
            byte[] chunk1data = chunks.get(1).data;
            if (chunk1data == null)
                return false;
            if (chunk1data.length != 20)
                return false;
            return true;
        }

        @Override
        public byte[] getHashFromScript(Script script) {
            return script.chunks.get(1).data;
        }
    },
    P2WSH("P2WSH", new PolicyType[]{MULTI, CUSTOM}) {
        @Override
        public Address getAddress(byte[] bytes) {
            return new P2WSHAddress(bytes);
        }

        @Override
        public Script getOutputScript(byte[] bytes) {
            List<ScriptChunk> chunks = new ArrayList<>();
            chunks.add(new ScriptChunk(OP_0, null));
            chunks.add(new ScriptChunk(bytes.length, bytes));

            return new Script(chunks);
        }

        @Override
        public boolean isScriptType(Script script) {
            List<ScriptChunk> chunks = script.chunks;
            if (chunks.size() != 2)
                return false;
            if (!chunks.get(0).equalsOpCode(OP_0))
                return false;
            byte[] chunk1data = chunks.get(1).data;
            if (chunk1data == null)
                return false;
            if (chunk1data.length != 32)
                return false;
            return true;
        }

        @Override
        public byte[] getHashFromScript(Script script) {
            return script.chunks.get(1).data;
        }
    };

    private final String name;
    private final PolicyType[] allowedPolicyTypes;

    ScriptType(String name, PolicyType[] allowedPolicyTypes) {
        this.name = name;
        this.allowedPolicyTypes = allowedPolicyTypes;
    }

    public String getName() {
        return name;
    }

    public PolicyType[] getAllowedPolicyTypes() {
        return allowedPolicyTypes;
    }

    public abstract Address getAddress(byte[] bytes);

    public abstract Script getOutputScript(byte[] bytes);

    public abstract boolean isScriptType(Script script);

    public abstract byte[] getHashFromScript(Script script);

    public Address[] getAddresses(Script script) {
        return new Address[] { getAddress(getHashFromScript(script)) };
    }

    public ECKey getPublicKeyFromScript(Script script) {
        throw new ProtocolException("Script type " + this + " does not contain a public key");
    }

    public ECKey[] getPublicKeysFromScript(Script script) {
        throw new ProtocolException("Script type " + this + " does not contain public keys");
    }

    public int getThreshold(Script script) {
        throw new ProtocolException("Script type " + this + " is not a multisig script");
    }

    public static final ScriptType[] SINGLE_HASH_TYPES = {P2PKH, P2SH, P2SH_P2WPKH, P2SH_P2WSH, P2WPKH, P2WSH};

    @Override
    public String toString() {
        return name;
    }
}
