open module com.sparrowwallet.drongo {
    requires org.bouncycastle.provider;
    requires de.mkammerer.argon2;
    requires org.slf4j;
    requires logback.core;
    requires logback.classic;
    requires json.simple;
    requires jeromq;
    exports com.sparrowwallet.drongo;
    exports com.sparrowwallet.drongo.psbt;
    exports com.sparrowwallet.drongo.protocol;
    exports com.sparrowwallet.drongo.address;
    exports com.sparrowwallet.drongo.crypto;
    exports com.sparrowwallet.drongo.wallet;
    exports com.sparrowwallet.drongo.policy;
    exports com.sparrowwallet.drongo.uri;
}