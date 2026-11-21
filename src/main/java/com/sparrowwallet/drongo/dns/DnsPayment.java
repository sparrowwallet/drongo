package com.sparrowwallet.drongo.dns;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.uri.BitcoinURI;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.util.Arrays;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.sparrowwallet.drongo.dns.RecordUtils.fromWire;

public record DnsPayment(String hrn, BitcoinURI bitcoinURI, byte[] proofChain) {
    public static final Pattern HRN_PATTERN = Pattern.compile("[A-Za-z0-9_+-]+(?:\\.[A-Za-z0-9_+-]+)*@[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+)*\\.[A-Za-z0-9_-]{2,}");

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

    public boolean hasOtherNetworkSilentPaymentAddress() {
        return Arrays.stream(Network.values()).map(Network::getSilentPaymentsAddressHrp)
                .anyMatch(hrp -> !hrp.equals(BitcoinURI.FIELD_SILENT_PAYMENTS_ADDRESS) && bitcoinURI.getParameterByName(hrp) != null);
    }

    public static Optional<String> getHrn(String value) {
        String hrn = value.startsWith("₿") ? value.substring(1) : value;
        return HRN_PATTERN.matcher(hrn).matches() ? Optional.of(hrn) : Optional.empty();
    }
}
