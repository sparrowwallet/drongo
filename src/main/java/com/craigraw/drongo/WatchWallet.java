package com.craigraw.drongo;

import com.craigraw.drongo.address.Address;
import com.craigraw.drongo.crypto.*;

import java.util.HashMap;
import java.util.List;

public class WatchWallet {
    private static final int LOOK_AHEAD_LIMIT = 500;

    private String name;
    private OutputDescriptor outputDescriptor;
    private DeterministicHierarchy hierarchy;

    private HashMap<Address,List<ChildNumber>> addresses = new HashMap<>(LOOK_AHEAD_LIMIT*2);

    public WatchWallet(String name, String descriptor) {
        this.name = name;
        this.outputDescriptor = OutputDescriptor.getOutputDescriptor(descriptor);
        this.hierarchy = new DeterministicHierarchy(outputDescriptor.getPubKey());
    }

    public void initialiseAddresses() {
        if(outputDescriptor.describesMultipleAddresses()) {
            for(int index = 0; index <= LOOK_AHEAD_LIMIT; index++) {
                List<ChildNumber> receivingDerivation = outputDescriptor.getReceivingDerivation(index);
                Address address = getAddress(receivingDerivation);
                addresses.put(address, receivingDerivation);
            }

            for(int index = 0; index <= LOOK_AHEAD_LIMIT; index++) {
                List<ChildNumber> changeDerivation = outputDescriptor.getChangeDerivation(index);
                Address address = getAddress(changeDerivation);
                addresses.put(address, changeDerivation);
            }
        } else {
            List<ChildNumber> derivation = outputDescriptor.getChildDerivation();
            Address address = getAddress(derivation);
            addresses.put(address, derivation);
        }
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

    private Address getAddress(List<ChildNumber> path) {
        DeterministicKey childKey = hierarchy.get(path);
        return outputDescriptor.getAddress(childKey);
    }
}
