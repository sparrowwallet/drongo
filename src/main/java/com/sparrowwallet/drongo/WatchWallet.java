package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.*;

import java.util.HashMap;
import java.util.List;

public class WatchWallet {
    private static final int LOOK_AHEAD_LIMIT = 500;

    private String name;
    private OutputDescriptor outputDescriptor;

    private HashMap<Address,List<ChildNumber>> addresses = new HashMap<>(LOOK_AHEAD_LIMIT*2);

    public WatchWallet(String name, String descriptor) {
        this.name = name;
        this.outputDescriptor = OutputDescriptor.getOutputDescriptor(descriptor);
    }

    public void initialiseAddresses() {
        if(outputDescriptor.describesMultipleAddresses()) {
            for(int index = 0; index <= LOOK_AHEAD_LIMIT; index++) {
                List<ChildNumber> receivingDerivation = outputDescriptor.getReceivingDerivation(index);
                Address address = getReceivingAddress(index);
                addresses.put(address, receivingDerivation);
            }

            for(int index = 0; index <= LOOK_AHEAD_LIMIT; index++) {
                List<ChildNumber> changeDerivation = outputDescriptor.getChangeDerivation(index);
                Address address = getChangeAddress(index);
                addresses.put(address, changeDerivation);
            }
        } else {
            List<ChildNumber> derivation = outputDescriptor.getChildDerivation();
            Address address = outputDescriptor.getAddress(derivation);
            addresses.put(address, derivation);
        }
    }

    public String getName() {
        return name;
    }

    public boolean containsAddress(Address address) {
        return addresses.containsKey(address);
    }

    public List<ChildNumber> getAddressPath(Address address) {
        return addresses.get(address);
    }

    public Address getReceivingAddress(int index) {
        return getAddress(outputDescriptor.getReceivingDerivation(index));
    }

    public Address getChangeAddress(int index) {
        return getAddress(outputDescriptor.getChangeDerivation(index));
    }

    public OutputDescriptor getOutputDescriptor() {
        return outputDescriptor;
    }

    public Address getAddress(List<ChildNumber> path) {
        return outputDescriptor.getAddress(path);
    }
}
