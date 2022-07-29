package com.sparrowwallet.drongo.uri;

import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.address.InvalidAddressException;
import com.sparrowwallet.drongo.wallet.Payment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.*;

import static com.sparrowwallet.drongo.protocol.Transaction.*;

/**
 * <p>Provides a standard implementation of a Bitcoin URI with support for the following:</p>
 *
 * <ul>
 * <li>URLEncoded URIs (as passed in by IE on the command line)</li>
 * <li>BIP21 names (including the "req-" prefix handling requirements)</li>
 * </ul>
 *
 * <h2>Accepted formats</h2>
 *
 * <p>The following input forms are accepted:</p>
 *
 * <ul>
 * <li>{@code bitcoin:<address>}</li>
 * <li>{@code bitcoin:<address>?<name1>=<value1>&<name2>=<value2>} with multiple
 * additional name/value pairs</li>
 * </ul>
 *
 * <p>The name/value pairs are processed as follows.</p>
 * <ol>
 * <li>URL encoding is stripped and treated as UTF-8</li>
 * <li>names prefixed with {@code req-} are treated as required and if unknown or conflicting cause a parse exception</li>
 * <li>Unknown names not prefixed with {@code req-} are added to a Map, accessible by parameter name</li>
 * <li>Known names not prefixed with {@code req-} are processed unless they are malformed</li>
 * </ol>
 *
 * <p>The following names are known and have the following formats:</p>
 * <ul>
 * <li>{@code amount} decimal value to 8 dp (e.g. 0.12345678) <b>Note that the
 * exponent notation is not supported any more</b></li>
 * <li>{@code label} any URL encoded alphanumeric</li>
 * <li>{@code message} any URL encoded alphanumeric</li>
 * </ul>
 *
 * @author Andreas Schildbach (initial code)
 * @author Jim Burton (enhancements for MultiBit)
 * @author Gary Rowe (BIP21 support)
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki">BIP 0021</a>
 */
public class BitcoinURI {
    private static final Logger log = LoggerFactory.getLogger(BitcoinURI.class);

    public static final String FIELD_MESSAGE = "message";
    public static final String FIELD_LABEL = "label";
    public static final String FIELD_AMOUNT = "amount";
    public static final String FIELD_ADDRESS = "address";
    public static final String FIELD_PAYMENT_REQUEST_URL = "r";
    public static final String FIELD_PAYJOIN_URL = "pj";
    public static final String FIELD_PAYJOIN_OUTPUT_SUBSTITUTION = "pjos";

    public static final String BITCOIN_SCHEME = "bitcoin";
    private static final String ENCODED_SPACE_CHARACTER = "%20";
    private static final String AMPERSAND_SEPARATOR = "&";
    private static final String QUESTION_MARK_SEPARATOR = "?";

    public static final DecimalFormat BTC_FORMAT = new DecimalFormat("0", DecimalFormatSymbols.getInstance(Locale.ENGLISH));
    public static final int SMALLEST_UNIT_EXPONENT = 8;

    /**
     * Contains all the parameters in the order in which they were processed
     */
    private final Map<String, Object> parameterMap = new LinkedHashMap<>();

    /**
     * Constructs a new BitcoinURI from the given string.
     *
     * @param input The raw URI data to be parsed (see class comments for accepted formats)
     * @throws BitcoinURIParseException if the URI is not syntactically or semantically valid.
     */
    public BitcoinURI(String input) throws BitcoinURIParseException {
        // Attempt to parse the URI
        URI uri;
        try {
            uri = new URI(input);
        } catch(URISyntaxException e) {
            throw new BitcoinURIParseException("Bad URI syntax", e);
        }

        // URI is formed as  bitcoin:<address>?<query parameters>
        // blockchain.info generates URIs of non-BIP compliant form bitcoin://address?....

        if (!BITCOIN_SCHEME.equalsIgnoreCase(uri.getScheme())) {
            throw new BitcoinURIParseException("Unsupported URI scheme: " + uri.getScheme());
        }

        String schemeSpecificPart = uri.getRawSchemeSpecificPart().startsWith("//")
                ? uri.getRawSchemeSpecificPart().substring(2)
                : uri.getRawSchemeSpecificPart();

        // Split off the address from the rest of the query parameters.
        String[] addressSplitTokens = schemeSpecificPart.split("\\?", 2);
        if(addressSplitTokens.length == 0) {
            throw new BitcoinURIParseException("No data found after the bitcoin: prefix");
        }
        String addressToken = addressSplitTokens[0];  // may be empty!

        String[] nameValuePairTokens;
        if(addressSplitTokens.length == 1) {
            // Only an address is specified - use an empty '<name>=<value>' token array.
            nameValuePairTokens = new String[]{};
        } else {
            // Split into '<name>=<value>' tokens.
            nameValuePairTokens = addressSplitTokens[1].split("&");
        }

        // Attempt to parse the rest of the URI parameters.
        parseParameters(addressToken, nameValuePairTokens);

        if(!addressToken.isEmpty()) {
            // Attempt to parse the addressToken as a Bitcoin address for this network
            try {
                Address address = Address.fromString(addressToken);
                putWithValidation(FIELD_ADDRESS, address);
            } catch(final InvalidAddressException e) {
                throw new BitcoinURIParseException("Invalid address", e);
            }
        }

        if(addressToken.isEmpty() && getPaymentRequestUrl() == null) {
            throw new BitcoinURIParseException("No address and no r= parameter found");
        }
    }

    /**
     * @param nameValuePairTokens The tokens representing the name value pairs (assumed to be
     *                            separated by '=' e.g. 'amount=0.2')
     */
    private void parseParameters(String addressToken, String[] nameValuePairTokens) throws BitcoinURIParseException {
        // Attempt to decode the rest of the tokens into a parameter map.
        for(String nameValuePairToken : nameValuePairTokens) {
            final int sepIndex = nameValuePairToken.indexOf('=');
            if(sepIndex == -1) {
                throw new BitcoinURIParseException("Malformed Bitcoin URI - no separator in '" + nameValuePairToken + "'");
            }
            if(sepIndex == 0) {
                throw new BitcoinURIParseException("Malformed Bitcoin URI - empty name '" + nameValuePairToken + "'");
            }
            final String nameToken = nameValuePairToken.substring(0, sepIndex).toLowerCase(Locale.ROOT);
            final String valueToken = nameValuePairToken.substring(sepIndex + 1);

            // Parse the amount.
            if(FIELD_AMOUNT.equals(nameToken) && !valueToken.isEmpty()) {
                // Decode the amount (contains an optional decimal component to 8dp).
                try {
                    long amount = new BigDecimal(valueToken.replace(',', '.')).movePointRight(SMALLEST_UNIT_EXPONENT).longValueExact();
                    if(amount > MAX_BITCOIN * SATOSHIS_PER_BITCOIN) {
                        throw new BitcoinURIParseException("Maximum amount exceeded");
                    }
                    if(amount < 0) {
                        throw new ArithmeticException("Negative amount specified");
                    }
                    putWithValidation(FIELD_AMOUNT, amount);
                } catch(IllegalArgumentException e) {
                    throw new OptionalFieldValidationException(String.format(Locale.US, "'%s' is not a valid amount", valueToken), e);
                } catch(ArithmeticException e) {
                    throw new OptionalFieldValidationException(String.format(Locale.US, "'%s' has too many decimal places", valueToken), e);
                }
            } else {
                if(nameToken.startsWith("req-")) {
                    // A required parameter that we do not know about.
                    throw new RequiredFieldValidationException("'" + nameToken + "' is required but not known, this URI is not valid");
                } else {
                    // Known fields and unknown parameters that are optional.
                    if(valueToken.length() > 0) {
                        putWithValidation(nameToken, URLDecoder.decode(valueToken, StandardCharsets.UTF_8));
                    }
                }
            }
        }

        // Note to the future: when you want to implement 'req-expires' have a look at commit 410a53791841
        // which had it in.
    }

    /**
     * Put the value against the key in the map checking for duplication. This avoids address field overwrite etc.
     *
     * @param key   The key for the map
     * @param value The value to store
     */
    private void putWithValidation(String key, Object value) throws BitcoinURIParseException {
        if(parameterMap.containsKey(key)) {
            throw new BitcoinURIParseException(String.format(Locale.US, "'%s' is duplicated, URI is invalid", key));
        } else {
            parameterMap.put(key, value);
        }
    }

    /**
     * The Bitcoin address from the URI, if one was present. It's possible to have Bitcoin URI's with no address if a
     * r= payment protocol parameter is specified, though this form is not recommended as older wallets can't understand
     * it.
     */
    public Address getAddress() {
        return (Address)parameterMap.get(FIELD_ADDRESS);
    }

    /**
     * @return The amount name encoded using a pure integer value based at
     * 10,000,000 units is 1 BTC. May be null if no amount is specified
     */
    public Long getAmount() {
        return (Long)parameterMap.get(FIELD_AMOUNT);
    }

    /**
     * @return The label from the URI.
     */
    public String getLabel() {
        return (String)parameterMap.get(FIELD_LABEL);
    }

    /**
     * @return The message from the URI.
     */
    public String getMessage() {
        return (String)parameterMap.get(FIELD_MESSAGE);
    }

    /**
     * @return The URL where a payment request (as specified in BIP 70) may
     * be fetched.
     */
    public final String getPaymentRequestUrl() {
        return (String)parameterMap.get(FIELD_PAYMENT_REQUEST_URL);
    }

    /**
     * Returns the URLs where a payment request (as specified in BIP 70) may be fetched. The first URL is the main URL,
     * all subsequent URLs are fallbacks.
     */
    public List<String> getPaymentRequestUrls() {
        ArrayList<String> urls = new ArrayList<>();
        while(true) {
            int i = urls.size();
            String paramName = FIELD_PAYMENT_REQUEST_URL + (i > 0 ? Integer.toString(i) : "");
            String url = (String)parameterMap.get(paramName);
            if(url == null) {
                break;
            }
            urls.add(url);
        }
        Collections.reverse(urls);
        return urls;
    }

    /**
     * @return The URL where a payjoin endpoint (as specified in BIP 78) may be specified.
     */
    public final URI getPayjoinUrl() {
        String payjoinUrl = (String)parameterMap.get(FIELD_PAYJOIN_URL);
        if(payjoinUrl != null) {
            try {
                URI uri = new URI(payjoinUrl);
                if(uri.getScheme().equals("https") || uri.getHost().endsWith(".onion")) {
                    return uri;
                } else {
                    log.error("Insecure payjoin URL provided, must be https or .onion: " + payjoinUrl);
                }
            } catch(URISyntaxException e) {
                log.error("Invalid payjoin URL provided", e);
            }
        }

        return null;
    }

    /**
     * @return Whether to allow output substitution in the payjoin proposal transaction.
     */
    public final boolean isPayjoinOutputSubstitutionAllowed() {
        return !"0".equals(parameterMap.get(FIELD_PAYJOIN_OUTPUT_SUBSTITUTION));
    }

    /**
     * @param name The name of the parameter
     * @return The parameter value, or null if not present
     */
    public Object getParameterByName(String name) {
        return parameterMap.get(name);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder("BitcoinURI[");
        boolean first = true;
        for(Map.Entry<String, Object> entry : parameterMap.entrySet()) {
            if(first) {
                first = false;
            } else {
                builder.append(",");
            }
            builder.append("'").append(entry.getKey()).append("'=").append("'").append(entry.getValue()).append("'");
        }
        builder.append("]");
        return builder.toString();
    }

    public Payment toPayment() {
        long amount = getAmount() == null ? -1 : getAmount();
        return new Payment(getAddress(), getLabel(), amount, false);
    }

    /**
     * Constructs a new BitcoinURI from the given address.
     *
     * @param address The address forming the base of the URI
     */
    public static BitcoinURI fromAddress(Address address) {
        try {
            return new BitcoinURI(BITCOIN_SCHEME + ":" + address.toString());
        } catch(BitcoinURIParseException e) {
            //Can't happen
            return null;
        }
    }

    /**
     * Simple Bitcoin URI builder using known good fields.
     *
     * @param address The Bitcoin address
     * @param amount  The amount
     * @param label   A label
     * @param message A message
     * @return A String containing the Bitcoin URI
     */
    public static String convertToBitcoinURI(Address address, Long amount, String label, String message) {
        return convertToBitcoinURI(address.toString(), amount, label, message);
    }

    /**
     * Simple Bitcoin URI builder using known good fields.
     *
     * @param address The Bitcoin address
     * @param amount  The amount
     * @param label   A label
     * @param message A message
     * @return A String containing the Bitcoin URI
     */
    public static String convertToBitcoinURI(String address, Long amount, String label, String message) {
        if(amount != null && amount < 0) {
            throw new IllegalArgumentException("Amount must be positive");
        }

        StringBuilder builder = new StringBuilder();
        builder.append(BITCOIN_SCHEME).append(":").append(address);

        boolean questionMarkHasBeenOutput = false;

        if(amount != null) {
            builder.append(QUESTION_MARK_SEPARATOR).append(FIELD_AMOUNT).append("=");
            BTC_FORMAT.setMaximumFractionDigits(8);
            builder.append(BTC_FORMAT.format(amount.doubleValue() / SATOSHIS_PER_BITCOIN));
            questionMarkHasBeenOutput = true;
        }

        if(label != null && !label.isEmpty()) {
            if(questionMarkHasBeenOutput) {
                builder.append(AMPERSAND_SEPARATOR);
            } else {
                builder.append(QUESTION_MARK_SEPARATOR);
                questionMarkHasBeenOutput = true;
            }
            builder.append(FIELD_LABEL).append("=").append(encodeURLString(label));
        }

        if(message != null && !message.isEmpty()) {
            if(questionMarkHasBeenOutput) {
                builder.append(AMPERSAND_SEPARATOR);
            } else {
                builder.append(QUESTION_MARK_SEPARATOR);
            }
            builder.append(FIELD_MESSAGE).append("=").append(encodeURLString(message));
        }

        return builder.toString();
    }

    /**
     * Encode a string using URL encoding
     *
     * @param stringToEncode The string to URL encode
     */
    static String encodeURLString(String stringToEncode) {
        return java.net.URLEncoder.encode(stringToEncode, StandardCharsets.UTF_8).replace("+", ENCODED_SPACE_CHARACTER);
    }
}
