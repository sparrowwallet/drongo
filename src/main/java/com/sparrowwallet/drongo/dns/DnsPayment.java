package com.sparrowwallet.drongo.dns;

import com.sparrowwallet.drongo.uri.BitcoinURI;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static com.sparrowwallet.drongo.dns.RecordUtils.fromWire;

public record DnsPayment(String hrn, BitcoinURI bitcoinURI, byte[] proofChain) {
    public String toString() {
        return "₿" + hrn;
    }

    public long getTTL() {
        long ttl = DnsPaymentCache.MAX_TTL_SECONDS;
        DNSInput in = new DNSInput(proofChain);
        while(in.remaining() > 0) {
            try {
                Record record = fromWire(in, Section.ANSWER, false);
                ttl = Math.min(ttl, record.getTTL());
            } catch(WireParseException e) {
                //ignore
            }
        }

        return ttl;
    }

    public boolean hasAddress() {
        return bitcoinURI.getAddress() != null;
    }

    public boolean hasSilentPaymentAddress() {
        return bitcoinURI.getSilentPaymentAddress() != null;
    }

    public static Optional<String> getHrn(String value) {
        String hrn = value;
        if(value.endsWith(".")) {
            return Optional.empty();
        }

        if(hrn.startsWith("₿")) {
            hrn = hrn.substring(1);
        }

        String[] addressParts = hrn.split("@");
        if(addressParts.length == 2 && addressParts[1].indexOf('.') > -1 && addressParts[1].substring(addressParts[1].indexOf('.') + 1).length() > 1 &&
                StandardCharsets.US_ASCII.newEncoder().canEncode(hrn)) {
            return Optional.of(hrn);
        }

        return Optional.empty();
    }
}
