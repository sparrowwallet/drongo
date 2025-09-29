package com.sparrowwallet.drongo.dns;

import com.sparrowwallet.drongo.uri.BitcoinURI;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

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
}
