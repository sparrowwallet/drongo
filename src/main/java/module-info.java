open module com.sparrowwallet.drongo {
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pg;
    requires org.pgpainless.core;
    requires de.mkammerer.argon2.nolibs;
    requires org.slf4j;
    requires ch.qos.logback.core;
    requires ch.qos.logback.classic;
    requires org.dnsjava;
    requires com.github.benmanes.caffeine;
    exports com.sparrowwallet.drongo;
    exports com.sparrowwallet.drongo.psbt;
    exports com.sparrowwallet.drongo.protocol;
    exports com.sparrowwallet.drongo.address;
    exports com.sparrowwallet.drongo.crypto;
    exports com.sparrowwallet.drongo.wallet;
    exports com.sparrowwallet.drongo.pgp;
    exports com.sparrowwallet.drongo.policy;
    exports com.sparrowwallet.drongo.uri;
    exports com.sparrowwallet.drongo.bip47;
    exports com.sparrowwallet.drongo.dns;
    exports com.sparrowwallet.drongo.wallet.bip93;
    exports com.sparrowwallet.drongo.wallet.slip39;
    exports com.sparrowwallet.drongo.silentpayments;
    exports org.bitcoin;
}