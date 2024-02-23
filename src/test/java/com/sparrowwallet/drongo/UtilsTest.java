package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.address.InvalidAddressException;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.Wallet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class UtilsTest {
    @Test
    public void reverseBytes() throws InvalidAddressException {
        Address address = Address.fromString("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");

        byte[] hash = Sha256Hash.hash(address.getOutputScript().getProgram());
        byte[] reversed = Utils.reverseBytes(hash);

        String actual = Utils.bytesToHex(reversed);

        Assertions.assertEquals("8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161", actual);
    }
}
