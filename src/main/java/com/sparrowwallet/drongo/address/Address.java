package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.protocol.Base58;
import com.sparrowwallet.drongo.protocol.Bech32;
import com.sparrowwallet.drongo.protocol.Network;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;

import java.io.Console;
import java.util.Arrays;

public abstract class Address {
    protected final Network network;
    protected final byte[] hash;

    public Address(Network network, byte[] hash) {
        this.network = network;
        this.hash = hash;
    }

    public Network getNetwork() {
        return network;
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
    
    /* Convienience function to try all valid network types when parsing address string */
    public static Address fromStringAnyNetwork(String address) throws InvalidAddressException {
        for (Network network : Network.values()) {
            try {
                return Address.fromString(network, address);
            } catch (InvalidAddressException e) {
            }
        }
        throw new InvalidAddressException("Could not parse invalid address " + address);
    }

    public static Address fromString(Network network, String address) throws InvalidAddressException {
        Exception nested = null;

        if(address != null && address.length() > 0 && network.legacyPrefixes.contains(String.valueOf(address.charAt(0)))) {
            try {
                byte[] decodedBytes = Base58.decodeChecked(address);
                if(decodedBytes.length == 21) {
                    int version = Byte.toUnsignedInt(decodedBytes[0]);
                    byte[] hash = Arrays.copyOfRange(decodedBytes, 1, 21);
                    if(version == network.pkhVersion) {
                        return new P2PKHAddress(network, hash);
                    }
                    if(version == network.shVersion) {
                        return new P2SHAddress(network, hash);
                    }
                }
            } catch (Exception e) {
                nested = e;
            }
        }

        if(address != null && address.startsWith(network.hrp)) {
            try {
                Bech32.Bech32Data data = Bech32.decode(address);
                if (data.hrp.equals(network.hrp)) {
                    int witnessVersion = data.data[0];
                    if (witnessVersion == 0) {
                        byte[] convertedProgram = Arrays.copyOfRange(data.data, 1, data.data.length);
                        byte[] witnessProgram = Bech32.convertBits(convertedProgram, 0, convertedProgram.length, 5, 8, false);
                        if (witnessProgram.length == 20) {
                            return new P2WPKHAddress(network, witnessProgram);
                        }
                        if (witnessProgram.length == 32) {
                            return new P2WSHAddress(network, witnessProgram);
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
