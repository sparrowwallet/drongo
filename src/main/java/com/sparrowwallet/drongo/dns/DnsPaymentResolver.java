package com.sparrowwallet.drongo.dns;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.uri.BitcoinURI;
import com.sparrowwallet.drongo.uri.BitcoinURIParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import org.xbill.DNS.dnssec.ValidatingResolver;
import org.xbill.DNS.lookup.LookupResult;
import org.xbill.DNS.lookup.LookupSession;
import org.xbill.DNS.lookup.NoSuchDomainException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutionException;

import static com.sparrowwallet.drongo.uri.BitcoinURI.BITCOIN_SCHEME;

public class DnsPaymentResolver {
    private static final Logger log = LoggerFactory.getLogger(DnsPaymentResolver.class);

    private static final String BITCOIN_URI_PREFIX = BITCOIN_SCHEME + ":";
    private static final String DEFAULT_RESOLVER_IP_ADDRESS = "8.8.8.8";

    static String ROOT = ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n" +
            ". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16";

    private final String hrn;
    private final String domain;
    private final Clock clock;

    public DnsPaymentResolver(String hrn) {
        this(hrn, Clock.systemUTC());
    }

    public DnsPaymentResolver(String hrn, Clock clock) {
        if(!StandardCharsets.US_ASCII.newEncoder().canEncode(hrn)) {
            throw new IllegalArgumentException("Invalid HRN containing non-ASCII characters: " + hrn);
        }
        this.hrn = hrn;
        String[] parts = hrn.split("@");
        if(parts.length != 2) {
            throw new IllegalArgumentException("Invalid HRN: " + hrn);
        }
        this.domain = parts[0] + ".user._bitcoin-payment." + parts[1];
        this.clock = clock;
    }

    public Optional<DnsPayment> resolve() throws IOException, DnsPaymentValidationException, BitcoinURIParseException, ExecutionException, InterruptedException {
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
    public Optional<DnsPayment> resolve(String resolverIpAddress) throws IOException, DnsPaymentValidationException, BitcoinURIParseException, ExecutionException, InterruptedException {
        log.debug("Resolving payment record for: " + domain);

        PersistingResolver persistingResolver = new PersistingResolver(resolverIpAddress);
        ValidatingResolver validatingResolver = new ValidatingResolver(persistingResolver, clock);
        validatingResolver.loadTrustAnchors(new ByteArrayInputStream(ROOT.getBytes(StandardCharsets.US_ASCII)));
        validatingResolver.setEDNS(0, 0, ExtendedFlags.DO);
        AuthenticatingResolver authenticatingResolver = new AuthenticatingResolver(validatingResolver);

        try {
            LookupSession lookupSession = LookupSession.builder().resolver(authenticatingResolver).build();
            LookupResult result = lookupSession.lookupAsync(getName(), Type.TXT, DClass.IN).toCompletableFuture().get();
            if(result.getRecords().isEmpty()) {
                return Optional.empty();
            }

            String strBitcoinUri = getBitcoinURI(result.getRecords());
            if(strBitcoinUri.isEmpty()) {
                return Optional.empty();
            }
            BitcoinURI bitcoinURI = new BitcoinURI(strBitcoinUri);
            validateResponse(authenticatingResolver, new ArrayList<>(persistingResolver.getChain()));

            byte[] proofChain = persistingResolver.chainToWire();
            log.debug("Resolved " + hrn + " with proof " + Utils.bytesToHex(proofChain));

            return Optional.of(new DnsPayment(hrn, bitcoinURI, proofChain));
        } catch(ExecutionException e) {
            if(e.getCause() instanceof NoSuchDomainException) {
                return Optional.empty();
            } else {
                throw e;
            }
        }
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
    public Optional<DnsPayment> resolve(byte[] proofChain) throws IOException, DnsPaymentValidationException, BitcoinURIParseException, ExecutionException, InterruptedException {
        OfflineResolver offlineResolver = new OfflineResolver(proofChain);
        ValidatingResolver offlineValidatingResolver = new ValidatingResolver(offlineResolver, clock);
        offlineValidatingResolver.loadTrustAnchors(new ByteArrayInputStream(ROOT.getBytes(StandardCharsets.US_ASCII)));
        AuthenticatingResolver authenticatingResolver = new AuthenticatingResolver(offlineValidatingResolver);

        Instant now = clock.instant();
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

        try {
            LookupSession lookupSession = LookupSession.builder().resolver(authenticatingResolver).build();
            LookupResult result = lookupSession.lookupAsync(getName(), Type.TXT, DClass.IN).toCompletableFuture().get();
            if(result.getRecords().isEmpty()) {
                return Optional.empty();
            }

            String strBitcoinUri = getBitcoinURI(result.getRecords());
            if(strBitcoinUri.isEmpty()) {
                return Optional.empty();
            }
            BitcoinURI bitcoinURI = new BitcoinURI(strBitcoinUri);
            validateResponse(authenticatingResolver, offlineResolver.getRecords());

            return Optional.of(new DnsPayment(hrn, bitcoinURI, proofChain));
        } catch(ExecutionException e) {
            if(e.getCause() instanceof NoSuchDomainException) {
                return Optional.empty();
            } else {
                throw e;
            }
        }
    }

    private Name getName() throws TextParseException {
        return Name.fromString(domain + ".");
    }

    private void validateResponse(AuthenticatingResolver resolver, List<Record> records) throws DnsPaymentValidationException {
        boolean isValidated = resolver.isAuthenticated();
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
