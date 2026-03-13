package org.bitcoin;

import com.sparrowwallet.drongo.NativeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
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
        String osName = System.getProperty("os.name");
        String osArch = System.getProperty("os.arch");
        String libName;
        if(osName.startsWith("Windows")) {
            libName = "libsecp256k1-0.dll";
        } else if(osName.startsWith("Mac")) {
            libName = "libsecp256k1.dylib";
        } else {
            libName = "libsecp256k1.so";
        }

        // Try loading from the application image lib/ directory
        String javaHome = System.getProperty("java.home");
        if(javaHome != null) {
            File libFile = new File(javaHome, "lib" + java.io.File.separator + libName);
            if(libFile.exists()) {
                try {
                    System.load(libFile.getAbsolutePath());
                    return true;
                } catch(UnsatisfiedLinkError e) {
                    log.debug("Could not load libsecp256k1 from java.home, falling back to JAR extraction", e);
                }
            }
        }

        // Fallback: extract from JAR
        try {
            if(osName.startsWith("Mac") && osArch.equals("aarch64")) {
                NativeUtils.loadLibraryFromJar("/native/osx/aarch64/" + libName);
            } else if(osName.startsWith("Mac")) {
                NativeUtils.loadLibraryFromJar("/native/osx/x64/" + libName);
            } else if(osName.startsWith("Windows")) {
                NativeUtils.loadLibraryFromJar("/native/windows/x64/" + libName);
            } else if(osArch.equals("aarch64")) {
                NativeUtils.loadLibraryFromJar("/native/linux/aarch64/" + libName);
            } else {
                NativeUtils.loadLibraryFromJar("/native/linux/x64/" + libName);
            }

            return true;
        } catch(UnsatisfiedLinkError | IOException e) {
            log.error("Error loading libsecp256k1 library", e);
        }

        return false;
    }

    private static native long secp256k1_init_context();
}
