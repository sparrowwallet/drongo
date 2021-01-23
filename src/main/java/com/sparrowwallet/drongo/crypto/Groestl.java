package com.sparrowwallet.drongo.crypto;

import fr.cryptohash.Groestl512;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Hash Engineering on 12/24/14 for the Groestl algorithm
 */
public class Groestl {

    private static final Logger log = LoggerFactory.getLogger(Groestl.class);
    private static boolean native_library_loaded = false;
    private static final Groestl512 digestGroestl = new Groestl512();

    static {
        try {
            System.loadLibrary("groestld");
            native_library_loaded = true;
        } catch(UnsatisfiedLinkError x) {
            native_library_loaded = false;
        } catch(Exception e) {
            native_library_loaded = false;
        }
    }

    public static byte[] digest(byte[] input, int offset, int length) {
        try {
            return native_library_loaded ? groestld_native(input, offset, length) : groestl(input, offset, length);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] digest(byte[] input) {
        try {
            return native_library_loaded ? groestld_native(input, 0, input.length) : groestl(input);
        } catch (Exception e) {
            return null;
        }
    }

    static native byte [] groestld_native(byte [] input, int offset, int len);

    static byte [] groestl(byte header[]) {
        Groestl512 hasher1 = new Groestl512();
        Groestl512 hasher2 = new Groestl512();

        byte [] hash1 = hasher1.digest(header);
        byte [] hash2 = hasher2.digest(hash1);

        byte [] hash = new byte [32];
        System.arraycopy(hash2, 0, hash, 0, 32);
        return hash;
    }

    static byte [] groestl(byte header[], int offset, int length) {
        digestGroestl.reset();
        digestGroestl.update(header, offset, length);
        byte [] hash1 = digestGroestl.digest();
        byte [] hash2 = digestGroestl.digest(hash1);

        byte [] hash = new byte [32];
        System.arraycopy(hash2, 0, hash, 0, 32);
        return hash;
    }
}
