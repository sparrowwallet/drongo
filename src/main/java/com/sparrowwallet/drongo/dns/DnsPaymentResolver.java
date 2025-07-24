package com.sparrowwallet.drongo.dns;

import com.sparrowwallet.drongo.uri.BitcoinURI;
import com.sparrowwallet.drongo.uri.BitcoinURIParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import org.xbill.DNS.dnssec.ValidatingResolver;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

import static com.sparrowwallet.drongo.uri.BitcoinURI.BITCOIN_SCHEME;

public class DnsPaymentResolver {
    private static final Logger log = LoggerFactory.getLogger(DnsPaymentResolver.class);

    private static final String BITCOIN_URI_PREFIX = BITCOIN_SCHEME + ":";
    private static final String DEFAULT_RESOLVER_IP_ADDRESS = "8.8.8.8";

    static String ROOT = ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n" +
            ". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16";

    private final String hrn;
    private final String domain;

    public DnsPaymentResolver(String hrn) {
        if(!StandardCharsets.US_ASCII.newEncoder().canEncode(hrn)) {
            throw new IllegalArgumentException("Invalid HRN containing non-ASCII characters: " + hrn);
        }
        this.hrn = hrn;
        String[] parts = hrn.split("@");
        if(parts.length != 2) {
            throw new IllegalArgumentException("Invalid HRN: " + hrn);
        }
        this.domain = parts[0] + ".user._bitcoin-payment." + parts[1];
    }

    public Optional<DnsPayment> resolve() throws IOException, DnsPaymentValidationException, BitcoinURIParseException {
        return resolve(DEFAULT_RESOLVER_IP_ADDRESS);
    }

    /**
     * Performs online resolution of the BIP 353 HRN via the configured resolver
     *
     * @param resolverIpAddress the IP address of the resolver to use for the DNS lookup
     * @return The DNS payment instruction, if present
     * @throws IOException Thrown for a general I/O error
     * @throws DnsPaymentValidationException Thrown for a DNSSEC or BIP 353 validation failure
     * @throws BitcoinURIParseException Thrown for an invalid BIP 21 URI
     */
    public Optional<DnsPayment> resolve(String resolverIpAddress) throws IOException, DnsPaymentValidationException, BitcoinURIParseException {
        log.debug("Resolving payment record for: " + domain);

        PersistingResolver persistingResolver = new PersistingResolver(resolverIpAddress);
        ValidatingResolver resolver = new ValidatingResolver(persistingResolver);
        resolver.loadTrustAnchors(new ByteArrayInputStream(ROOT.getBytes(StandardCharsets.US_ASCII)));
        resolver.setEDNS(0, 0, ExtendedFlags.DO);

        Lookup lookup = new Lookup(domain, Type.TXT);
        lookup.setResolver(resolver);

        Message query = getQuery();
        Message response = resolver.send(query);
        if(response.getSection(Section.ANSWER).isEmpty()) {
            return Optional.empty();
        }

        checkResponse(response, new ArrayList<>(persistingResolver.getChain()));
        String strBitcoinUri = getBitcoinURI(response.getSection(Section.ANSWER));
        if(strBitcoinUri.isEmpty()) {
            return Optional.empty();
        }
        BitcoinURI bitcoinURI = new BitcoinURI(strBitcoinUri);
        validateResponse(response, new ArrayList<>(persistingResolver.getChain()));

        return Optional.of(new DnsPayment(hrn, bitcoinURI, persistingResolver.chainToWire()));
    }

    /**
     * Performs offline resolution of the BIP 353 HRN via the provided authentication chain
     *
     * @param proofChain authentication chain of unsorted DNS records in wire format
     * @return The DNS payment instruction, if present
     * @throws IOException Thrown for a general I/O error
     * @throws DnsPaymentValidationException Thrown for a DNSSEC or BIP 353 validation failure
     * @throws BitcoinURIParseException Thrown for an invalid BIP 21 URI
     */
    public Optional<DnsPayment> resolve(byte[] proofChain) throws IOException, DnsPaymentValidationException, BitcoinURIParseException {
        OfflineResolver offlineResolver = new OfflineResolver(proofChain);
        ValidatingResolver offlineValidatingResolver = new ValidatingResolver(offlineResolver);
        offlineValidatingResolver.loadTrustAnchors(new ByteArrayInputStream(ROOT.getBytes(StandardCharsets.US_ASCII)));

        Instant now = Instant.now();
        Instant oneHourAgo = now.minusSeconds(3600);
        for(Record record : offlineResolver.getCachedSigs()) {
            if(record instanceof RRSIGRecord rrsig) {
                if(rrsig.getTimeSigned().isAfter(now)) {
                    throw new DnsPaymentValidationException("Invalid RRSIG record signed in the future");
                } else if(rrsig.getExpire().isBefore(oneHourAgo)) {
                    throw new DnsPaymentValidationException("Invalid RRSIG record expired earlier than 1 hour ago");
                }
            }
        }

        Message query = getQuery();
        Message offlineResponse = offlineValidatingResolver.send(query);
        if(offlineResponse.getSection(Section.ANSWER).isEmpty()) {
            return Optional.empty();
        }

        checkResponse(offlineResponse, offlineResolver.getRecords());
        String strBitcoinUri = getBitcoinURI(offlineResponse.getSection(Section.ANSWER));
        if(strBitcoinUri.isEmpty()) {
            throw new BitcoinURIParseException("The DNS record for " + hrn + " did not contain a Bitcoin URI");
        }
        BitcoinURI bitcoinURI = new BitcoinURI(strBitcoinUri);
        validateResponse(offlineResponse, offlineResolver.getRecords());

        return Optional.of(new DnsPayment(hrn, bitcoinURI, proofChain));
    }

    private Message getQuery() throws TextParseException {
        Name queryName = Name.fromString(domain + ".");
        Record question = Record.newRecord(queryName, Type.TXT, DClass.IN);
        return Message.newQuery(question);
    }

    private void checkResponse(Message response, List<Record> records) throws DnsPaymentValidationException {
        if(response.getRcode() != Rcode.NOERROR) {
            StringBuilder reason = new StringBuilder();
            for(RRset set : response.getSectionRRsets(Section.ADDITIONAL)) {
                if(set.getName().equals(Name.root) && set.getType() == Type.TXT && set.getDClass() == ValidatingResolver.VALIDATION_REASON_QCLASS) {
                    reason.append(((TXTRecord) set.first()).getStrings().getFirst());
                }
            }

            throw new DnsPaymentValidationException("DNS query for " + domain + " failed, " + (reason.isEmpty() ? "rcode was " + response.getRcode() : reason.toString()));
        }
    }

    private void validateResponse(Message response, List<Record> records) throws DnsPaymentValidationException {
        boolean isValidated = response.getHeader().getFlag(Flags.AD);
        if(!isValidated) {
            throw new DnsPaymentValidationException("DNSSEC validation failed, could not authenticate the payment instruction");
        }

        Map<Record, String> securityWarnings = RecordUtils.checkSecurityConstraints(records);
        if(!securityWarnings.isEmpty()) {
            Optional<String> optWarning = securityWarnings.entrySet().stream().map(e -> e.getKey().getName() + ": " + e.getValue()).reduce((a, b) -> a + "\n" + b);
            throw new DnsPaymentValidationException("DNSSEC validation failed with the following errors:\n" + optWarning.get());
        }
    }

    private String getBitcoinURI(List<Record> answers) throws DnsPaymentValidationException {
        StringBuilder uriBuilder = new StringBuilder();
        for(Record record : answers) {
            if(record.getType() == Type.TXT) {
                TXTRecord txt = (TXTRecord)record;
                List<String> strings = txt.getStrings();
                log.debug("Found TXT records for " + domain + ": " + strings);
                if(strings.isEmpty() || !strings.getFirst().startsWith(BITCOIN_URI_PREFIX)) {
                    continue;
                }
                if(strings.getFirst().startsWith(BITCOIN_URI_PREFIX) && !uriBuilder.isEmpty()) {
                    throw new DnsPaymentValidationException("Multiple TXT records found starting with " + BITCOIN_URI_PREFIX);
                }
                for(String s : strings) {
                    uriBuilder.append(s);
                }
            }
        }

        return uriBuilder.toString();
    }
}
