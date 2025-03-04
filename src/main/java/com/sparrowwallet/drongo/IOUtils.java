package com.sparrowwallet.drongo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class IOUtils {
    private static final Logger log = LoggerFactory.getLogger(IOUtils.class);

    public static FileType getFileType(File file) {
        try {
            String type = Files.probeContentType(file.toPath());
            if(type == null) {
                if(file.getName().toLowerCase(Locale.ROOT).endsWith("txn") || file.getName().toLowerCase(Locale.ROOT).endsWith("psbt")) {
                    return FileType.TEXT;
                }

                if(file.exists()) {
                    try(BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
                        String line = br.readLine();
                        if(line != null) {
                            if(line.startsWith("01000000") || line.startsWith("cHNid")) {
                                return FileType.TEXT;
                            } else if(line.startsWith("{")) {
                                return FileType.JSON;
                            }
                        }
                    }
                }

                return FileType.BINARY;
            } else if (type.equals("application/json")) {
                return FileType.JSON;
            } else if (type.startsWith("text")) {
                return FileType.TEXT;
            }
        } catch(IOException e) {
            //ignore
        }

        return FileType.UNKNOWN;
    }

    /**
     * Lists the contents of a resource directory. Non-recursive.
     * Works for regular files, JARs, and Java modules.
     *
     * @param clazz A class from the same module or package as the resources.
     * @param path The resource directory path (e.g., "myfolder/"). Must end with "/", must not start with "/".
     * @return An array of filenames (not full paths) in the specified directory.
     * @throws IOException If an I/O error occurs while accessing the resources.
     * @throws URISyntaxException If the path is invalid or unsupported.
     */
    public static String[] getResourceListing(Class<?> clazz, String path) throws URISyntaxException, IOException {
        URL dirURL = clazz.getClassLoader().getResource(path);
        if(dirURL != null && dirURL.getProtocol().equals("file")) {
            return new File(dirURL.toURI()).list();
        }

        if(dirURL == null) {
            String me = clazz.getName().replace(".", "/") + ".class";
            dirURL = clazz.getClassLoader().getResource(me);
            if(dirURL == null) {
                throw new IOException("Resource directory '" + path + "' not found for class " + clazz.getName());
            }
        }

        if(dirURL.getProtocol().equals("jar")) {
            String jarPath = dirURL.getPath().substring(5, dirURL.getPath().indexOf("!"));
            Set<String> result = new HashSet<>();

            try(JarFile jar = new JarFile(URLDecoder.decode(jarPath, StandardCharsets.UTF_8))) {
                Enumeration<JarEntry> entries = jar.entries();

                while(entries.hasMoreElements()) {
                    String name = entries.nextElement().getName();
                    if(name.startsWith(path)) {
                        String entry = name.substring(path.length());
                        int checkSubdir = entry.indexOf("/");
                        if(checkSubdir >= 0) {
                            entry = entry.substring(0, checkSubdir);
                        }
                        if(!entry.isEmpty()) {
                            result.add(entry);
                        }
                    }
                }
            }

            return result.toArray(new String[0]);
        }

        if(dirURL.getProtocol().equals("jrt")) {
            Module module = clazz.getModule();
            if(module == null || module.getName() == null) {
                throw new IOException("Class " + clazz.getName() + " is not in a named module");
            }
            try(java.nio.file.FileSystem jrtFs = FileSystems.newFileSystem(URI.create("jrt:/"), Collections.emptyMap())) {
                Path resourcePath = jrtFs.getPath("modules", module.getName(), path);
                try(var stream = Files.list(resourcePath)) {
                    return stream.filter(Files::isRegularFile).map(p -> p.getFileName().toString()).toArray(String[]::new);
                }
            }
        }

        throw new UnsupportedOperationException("Cannot list files for URL " + dirURL);
    }

    public static boolean deleteDirectory(File directory) {
        try(var stream = Files.walk(directory.toPath())) {
            stream.sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        } catch(IOException e) {
            return false;
        }

        return true;
    }

    public static boolean secureDelete(File file) {
        if(file.exists()) {
            long length = file.length();
            SecureRandom random = new SecureRandom();
            byte[] data = new byte[1024*1024];
            random.nextBytes(data);
            try(RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
                raf.seek(0);
                raf.getFilePointer();
                int pos = 0;
                while(pos < length) {
                    raf.write(data);
                    pos += data.length;
                }
            } catch(IOException e) {
                log.warn("Error overwriting file for deletion: " + file.getName(), e);
            }

            return file.delete();
        }

        return false;
    }
}
