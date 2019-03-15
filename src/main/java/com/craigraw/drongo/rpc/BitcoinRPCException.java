package com.craigraw.drongo.rpc;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class BitcoinRPCException extends RuntimeException {
    private static final Logger log = LoggerFactory.getLogger(BitcoinJSONRPCClient.class);

    private String rpcMethod;
    private String rpcParams;
    private int responseCode;
    private String responseMessage;
    private String response;
    private BitcoinRPCError rpcError;

    /**
     * Creates a new instance of <code>BitcoinRPCException</code> with response
     * detail.
     *
     * @param method the rpc method called
     * @param params the parameters sent
     * @param responseCode the HTTP code received
     * @param responseMessage the HTTP response message
     * @param response the error stream received
     */
    @SuppressWarnings("rawtypes")
    public BitcoinRPCException(String method,
                               String params,
                               int    responseCode,
                               String responseMessage,
                               String response) {
        super("RPC Query Failed (method: " + method + ", params: " + params + ", response code: " + responseCode + " responseMessage " + responseMessage + ", response: " + response);
        this.rpcMethod = method;
        this.rpcParams = params;
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
        this.response = response;
        if ( responseCode == 500 ) {
            // Bitcoind application error when handle the request
            // extract code/message for callers to handle
            try {
                JSONParser jsonParser = new JSONParser();
                Map error = (Map) ((Map)jsonParser.parse(response)).get("error");
                if ( error != null ) {
                    rpcError = new BitcoinRPCError(error);
                }
            } catch(ParseException e) {
                log.error("Could not parse bitcoind error", e);
            }
        }
    }

    public BitcoinRPCException(String method, String params, Throwable cause) {
        super("RPC Query Failed (method: " + method + ", params: " + params + ")", cause);
        this.rpcMethod = method;
        this.rpcParams = params;
    }

    /**
     * Constructs an instance of <code>BitcoinRPCException</code> with the
     * specified detail message.
     *
     * @param msg the detail message.
     */
    public BitcoinRPCException(String msg) {
        super(msg);
    }

    public BitcoinRPCException(BitcoinRPCError error) {
        super(error.getMessage());
        this.rpcError  = error;
    }

    public BitcoinRPCException(String message, Throwable cause) {
        super(message, cause);
    }

    public int getResponseCode() {
        return responseCode;
    }

    public String getRpcMethod() {
        return rpcMethod;
    }

    public String getRpcParams() {
        return rpcParams;
    }

    /**
     * @return the HTTP response message
     */
    public String getResponseMessage() {
        return responseMessage;
    }

    /**
     * @return response message from bitcored
     */
    public String getResponse() {
        return this.response;
    }

    /**
     * @return response message from bitcored
     */
    public BitcoinRPCError getRPCError() {
        return this.rpcError;
    }
}
