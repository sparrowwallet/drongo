package com.sparrowwallet.drongo;

import java.io.File;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The categories of application directory defined by the XDG Base Directory Specification.
 *
 * On platforms other than Windows, the XDG directory for a category is used if it already exists, allowing users to opt in
 * to the specification by creating and populating the directories themselves. Categories are resolved independently, so a
 * partially migrated installation continues to find the remainder of its files in the default application directory.
 *
 * On Windows, and where the XDG directory does not exist, the default application directory is used for every category.
 * An explicitly configured application home always takes precedence and disables XDG resolution entirely.
 */
public enum ApplicationDir {
    CONFIG("XDG_CONFIG_HOME", ".config"),
    DATA("XDG_DATA_HOME", ".local/share"),
    CACHE("XDG_CACHE_HOME", ".cache"),
    STATE("XDG_STATE_HOME", ".local/state");

    private final String environmentVariable;
    private final String defaultBasePath;
    private final Map<String, Boolean> xdgDirsInUse = new ConcurrentHashMap<>();

    ApplicationDir(String environmentVariable, String defaultBasePath) {
        this.environmentVariable = environmentVariable;
        this.defaultBasePath = defaultBasePath;
    }

    public File get(String application) {
        return get(application, false);
    }

    /**
     * Returns the directory for this category, which may not yet exist.
     *
     * @param application the application name, for example Sparrow
     * @param useDefault true to ignore any configured application home, giving a location that is common to all instances
     */
    public File get(String application, boolean useDefault) {
        return get(application, useDefault, getXdgDirInUse(application));
    }

    File get(String application, boolean useDefault, File xdgDirInUse) {
        if(!useDefault) {
            String applicationHome = System.getProperty(getHomeProperty(application));
            if(applicationHome != null) {
                return new File(applicationHome);
            }
        }

        if(xdgDirInUse != null) {
            return xdgDirInUse;
        }

        return getDefaultDir(application);
    }

    private File getXdgDirInUse(String application) {
        return getXdgDirInUse(application, getXdgDir(application));
    }

    /**
     * Returns the given XDG directory if this category has been migrated to it, or null if the default application directory should be used.
     *
     * The decision is pinned for the lifetime of the process. Creating an XDG directory while the application is running must not move the
     * files it has already opened elsewhere, which would otherwise split reads and writes across two locations.
     */
    File getXdgDirInUse(String application, File xdgDir) {
        return xdgDirsInUse.computeIfAbsent(application.toLowerCase(Locale.ROOT), name -> xdgDir != null && xdgDir.isDirectory()) ? xdgDir : null;
    }

    private File getXdgDir(String application) {
        return getXdgDir(application, System.getenv(environmentVariable), OsType.getCurrent());
    }

    /**
     * Returns the XDG directory for this category, whether or not it exists, or null if XDG resolution does not apply to this platform.
     */
    File getXdgDir(String application, String configuredBase, OsType osType) {
        if(osType == OsType.WINDOWS) {
            return null;
        }

        //Relative paths in the environment variable are invalid and must be ignored
        File baseDir = configuredBase != null && !configuredBase.isBlank() && new File(configuredBase).isAbsolute() ?
                new File(configuredBase) : new File(System.getProperty("user.home"), defaultBasePath);

        return new File(baseDir, application.toLowerCase(Locale.ROOT));
    }

    /**
     * Returns true if this category has been migrated to its XDG directory, and that directory is in use.
     */
    public boolean isXdg(String application) {
        File xdgDirInUse = getXdgDirInUse(application);
        return xdgDirInUse != null && xdgDirInUse.equals(get(application));
    }

    /**
     * Returns the single directory this application uses when the XDG Base Directory Specification is not followed.
     */
    public static File getDefaultDir(String application) {
        return getDefaultDir(application, OsType.getCurrent(), System.getenv("APPDATA"));
    }

    static File getDefaultDir(String application, OsType osType, String appData) {
        if(osType == OsType.WINDOWS) {
            File baseDir = appData != null && !appData.isBlank() ? new File(appData) : new File(System.getProperty("user.home"));
            return new File(baseDir, application.substring(0, 1).toUpperCase(Locale.ROOT) + application.substring(1).toLowerCase(Locale.ROOT));
        }

        return new File(System.getProperty("user.home"), "." + application.toLowerCase(Locale.ROOT));
    }

    public static String getHomeProperty(String application) {
        return application.toLowerCase(Locale.ROOT) + ".home";
    }
}
