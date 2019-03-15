package com.craigraw.drongo.rpc;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.nio.charset.Charset;
import java.util.*;

public class BitcoinJSONRPCClient {
    private static final Logger log = LoggerFactory.getLogger(BitcoinJSONRPCClient.class);
    public static final Charset QUERY_CHARSET = Charset.forName("ISO8859-1");
    public static final String RESPONSE_ID = "drongo";

    public final URL rpcURL;
    private final URL noAuthURL;
    private final String authStr;

    public BitcoinJSONRPCClient(String host, String port, String user, String password) {
        this.rpcURL = getConnectUrl(host, port, user, password);

        try {
            this.noAuthURL = new URI(rpcURL.getProtocol(), null, rpcURL.getHost(), rpcURL.getPort(), rpcURL.getPath(), rpcURL.getQuery(), null).toURL();
        } catch (MalformedURLException | URISyntaxException ex) {
            throw new IllegalArgumentException(rpcURL.toString(), ex);
        }

        this.authStr = rpcURL.getUserInfo() == null ? null : new String(Base64.getEncoder().encode(rpcURL.getUserInfo().getBytes(QUERY_CHARSET)), QUERY_CHARSET);
    }

    private URL getConnectUrl(String host, String port, String user, String password) {
        try {
            return new URL("http://" + user + ':' + password + "@" + host + ":" + (port == null ? "8332" : port) + "/");
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid RPC connection details", e);
        }
    }

    public Object query(String method, Object... o) throws BitcoinRPCException {
        HttpURLConnection conn;
        try {
            conn = (HttpURLConnection) noAuthURL.openConnection();

            conn.setDoOutput(true);
            conn.setDoInput(true);

            conn.setRequestProperty("Authorization", "Basic " + authStr);
            byte[] r = prepareRequest(method, o);
            log.debug("Bitcoin JSON-RPC request: " + new String(r, QUERY_CHARSET));
            conn.getOutputStream().write(r);
            conn.getOutputStream().close();
            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                InputStream errorStream = conn.getErrorStream();
                throw new BitcoinRPCException(method,
                        Arrays.deepToString(o),
                        responseCode,
                        conn.getResponseMessage(),
                        errorStream == null ? null : new String(loadStream(errorStream, true)));
            }
            return loadResponse(conn.getInputStream(), RESPONSE_ID, true);
        } catch (IOException ex) {
            throw new BitcoinRPCException(method, Arrays.deepToString(o), ex);
        }
    }

    protected byte[] prepareRequest(final String method, final Object... params) {
        return JSONObject.toJSONString(new LinkedHashMap<String, Object>() {
            {
                put("method", method);
                put("params", Arrays.asList(params));
                put("id", RESPONSE_ID);
                put("jsonrpc", "1.0");
            }
        }).getBytes(QUERY_CHARSET);
    }

    private static byte[] loadStream(InputStream in, boolean close) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        for (;;) {
            int nr = in.read(buffer);

            if (nr == -1)
                break;
            if (nr == 0)
                throw new IOException("Read timed out");

            o.write(buffer, 0, nr);
        }
        return o.toByteArray();
    }

    @SuppressWarnings("rawtypes")
    public Object loadResponse(InputStream in, Object expectedID, boolean close) throws IOException, BitcoinRPCException {
        try {
            String r = new String(loadStream(in, close), QUERY_CHARSET);
            log.debug("Bitcoin JSON-RPC response: " + r);
            try {
                JSONParser jsonParser = new JSONParser();
                Map response = (Map) jsonParser.parse(r);

                if (!expectedID.equals(response.get("id")))
                    throw new BitcoinRPCException("Wrong response ID (expected: " + String.valueOf(expectedID) + ", response: " + response.get("id") + ")");

                if (response.get("error") != null)
                    throw new BitcoinRPCException(new BitcoinRPCError((Map)response.get("error")));

                return response.get("result");
            } catch (ClassCastException | ParseException ex) {
                throw new BitcoinRPCException("Invalid server response format (data: \"" + r + "\")");
            }
        } finally {
            if (close)
                in.close();
        }
    }

    public String getRawTransaction(String txId) throws BitcoinRPCException {
        return (String) query("getrawtransaction", txId);
    }
}
