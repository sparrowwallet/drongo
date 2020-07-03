package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.Base58;
import com.sparrowwallet.drongo.protocol.Bech32;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;

import java.util.Arrays;

import static com.sparrowwallet.drongo.address.P2WPKHAddress.HRP;

public abstract class Address {
    protected final byte[] hash;

    public Address(byte[] hash) {
        this.hash = hash;
    }

    public byte[] getHash() {
        return hash;
    }

    public String getAddress() {
        return Base58.encodeChecked(getVersion(), hash);
    }

    public String toString() {
        return getAddress();
    }

    public abstract int getVersion();

    public abstract ScriptType getScriptType();

    public abstract Script getOutputScript();

    public abstract byte[] getOutputScriptData();

    public abstract String getOutputScriptDataType();

    public boolean equals(Object obj) {
        if(!(obj instanceof Address)) {
            return false;
        }

        Address address = (Address)obj;
        return address.getAddress().equals(this.getAddress());
    }

    public int hashCode() {
        return getAddress().hashCode();
    }

    public static Address fromString(String address) throws InvalidAddressException {
        Exception nested = null;

        if(address != null && (address.startsWith("1") || address.startsWith("3"))) {
            try {
                byte[] decodedBytes = Base58.decodeChecked(address);
                if(decodedBytes.length == 21) {
                    int version = decodedBytes[0];
                    byte[] hash = Arrays.copyOfRange(decodedBytes, 1, 21);
                    if(version == 0) {
                        return new P2PKHAddress(hash);
                    }
                    if(version == 5) {
                        return new P2SHAddress(hash);
                    }
                }
            } catch (Exception e) {
                nested = e;
            }
        }

        if(address != null && address.startsWith(HRP)) {
            try {
                Bech32.Bech32Data data = Bech32.decode(address);
                if (data.hrp.equals(HRP)) {
                    int witnessVersion = data.data[0];
                    if (witnessVersion == 0) {
                        byte[] convertedProgram = Arrays.copyOfRange(data.data, 1, data.data.length);
                        byte[] witnessProgram = Bech32.convertBits(convertedProgram, 0, convertedProgram.length, 5, 8, false);
                        if (witnessProgram.length == 20) {
                            return new P2WPKHAddress(witnessProgram);
                        }
                        if (witnessProgram.length == 32) {
                            return new P2WSHAddress(witnessProgram);
                        }
                    }
                }
            } catch (Exception e) {
                nested = e;
            }
        }

        if(nested != null) {
            throw new InvalidAddressException("Could not parse invalid address " + address, nested);
        }

        throw new InvalidAddressException("Could not parse invalid address " + address);
    }
}
