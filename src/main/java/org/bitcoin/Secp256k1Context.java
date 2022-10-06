package org.bitcoin;

import com.sparrowwallet.drongo.NativeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class Secp256k1Context {

    private static final boolean enabled; // true if the library is loaded
    private static final long context; // ref to pointer to context obj

    private static final Logger log = LoggerFactory.getLogger(Secp256k1Context.class);

    static { // static initializer
        enabled = loadLibrary();
        if(enabled) {
            context = secp256k1_init_context();
        } else {
            context = -1;
        }
    }

    public static boolean isEnabled() {
        return enabled;
    }

    public static long getContext() {
        if (!enabled)
            return -1; // sanity check
        return context;
    }

    private static boolean loadLibrary() {
        try {
            String osName = System.getProperty("os.name");
            String osArch = System.getProperty("os.arch");
            if(osName.startsWith("Mac") && osArch.equals("aarch64")) {
                NativeUtils.loadLibraryFromJar("/native/osx/aarch64/libsecp256k1.dylib");
            } else if(osName.startsWith("Mac")) {
                NativeUtils.loadLibraryFromJar("/native/osx/x64/libsecp256k1.dylib");
            } else if(osName.startsWith("Windows")) {
                NativeUtils.loadLibraryFromJar("/native/windows/x64/libsecp256k1-0.dll");
            } else if(osArch.equals("aarch64")) {
                NativeUtils.loadLibraryFromJar("/native/linux/aarch64/libsecp256k1.so");
            } else {
                NativeUtils.loadLibraryFromJar("/native/linux/x64/libsecp256k1.so");
            }

            return true;
        } catch(IOException e) {
            log.error("Error loading libsecp256k1 library", e);
        }

        return false;
    }

    private static native long secp256k1_init_context();
}
