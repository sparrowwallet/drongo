module com.craigraw.drongo {
    requires org.bouncycastle.provider;
    requires slf4j.api;
    exports com.craigraw.drongo;
    exports com.craigraw.drongo.psbt;
    exports com.craigraw.drongo.protocol;
    exports com.craigraw.drongo.address;
}