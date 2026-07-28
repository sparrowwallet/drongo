package com.sparrowwallet.drongo;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

public class ApplicationDirTest {
    private static final String APPLICATION = "Sparrow";
    private static final String HOME_PROPERTY = "sparrow.home";

    @TempDir
    private static Path tempDir;

    @Test
    public void testXdgDirs() {
        Assertions.assertEquals(new File("/xdg/config/sparrow"), ApplicationDir.CONFIG.getXdgDir(APPLICATION, "/xdg/config", OsType.UNIX));
        Assertions.assertEquals(new File("/xdg/data/sparrow"), ApplicationDir.DATA.getXdgDir(APPLICATION, "/xdg/data", OsType.UNIX));
        Assertions.assertEquals(new File("/xdg/cache/sparrow"), ApplicationDir.CACHE.getXdgDir(APPLICATION, "/xdg/cache", OsType.UNIX));
        Assertions.assertEquals(new File("/xdg/state/sparrow"), ApplicationDir.STATE.getXdgDir(APPLICATION, "/xdg/state", OsType.UNIX));
    }

    @Test
    public void testXdgDefaultBasePaths() {
        File home = new File(System.getProperty("user.home"));
        Assertions.assertEquals(new File(home, ".config/sparrow"), ApplicationDir.CONFIG.getXdgDir(APPLICATION, null, OsType.UNIX));
        Assertions.assertEquals(new File(home, ".local/share/sparrow"), ApplicationDir.DATA.getXdgDir(APPLICATION, null, OsType.UNIX));
        Assertions.assertEquals(new File(home, ".cache/sparrow"), ApplicationDir.CACHE.getXdgDir(APPLICATION, null, OsType.UNIX));
        Assertions.assertEquals(new File(home, ".local/state/sparrow"), ApplicationDir.STATE.getXdgDir(APPLICATION, null, OsType.UNIX));
    }

    @Test
    public void testXdgRelativeBasePathIgnored() {
        File home = new File(System.getProperty("user.home"));
        Assertions.assertEquals(new File(home, ".local/share/sparrow"), ApplicationDir.DATA.getXdgDir(APPLICATION, "relative/path", OsType.UNIX));
        Assertions.assertEquals(new File(home, ".local/share/sparrow"), ApplicationDir.DATA.getXdgDir(APPLICATION, "", OsType.UNIX));
    }

    @Test
    public void testXdgAppliedToMacos() {
        Assertions.assertEquals(new File("/xdg/data/sparrow"), ApplicationDir.DATA.getXdgDir(APPLICATION, "/xdg/data", OsType.MACOS));
    }

    @Test
    public void testXdgNotAppliedToWindows() {
        Assertions.assertNull(ApplicationDir.DATA.getXdgDir(APPLICATION, "/xdg/data", OsType.WINDOWS));
    }

    @Test
    public void testDefaultDir() {
        File home = new File(System.getProperty("user.home"));
        Assertions.assertEquals(new File("/appdata/Sparrow"), ApplicationDir.getDefaultDir(APPLICATION, OsType.WINDOWS, "/appdata"));
        Assertions.assertEquals(new File(home, ".sparrow"), ApplicationDir.getDefaultDir(APPLICATION, OsType.UNIX, null));
        Assertions.assertEquals(new File(home, ".sparrow"), ApplicationDir.getDefaultDir(APPLICATION, OsType.MACOS, null));
    }

    @Test
    public void testDefaultDirIsAbsoluteWithoutAppData() {
        //An unset APPDATA must not yield a directory relative to the working directory
        for(String appData : new String[] {null, "", " "}) {
            File defaultDir = ApplicationDir.getDefaultDir(APPLICATION, OsType.WINDOWS, appData);
            Assertions.assertTrue(defaultDir.isAbsolute());
            Assertions.assertEquals(new File(System.getProperty("user.home"), "Sparrow"), defaultDir);
        }
    }

    @Test
    public void testUnmigratedCategoryUsesDefaultDir() {
        for(ApplicationDir applicationDir : ApplicationDir.values()) {
            Assertions.assertEquals(ApplicationDir.getDefaultDir(APPLICATION), applicationDir.get(APPLICATION, false, null));
        }
    }

    @Test
    public void testMigratedCategoryUsesXdgDir() {
        File xdgDir = tempDir.resolve("migrated").resolve("sparrow").toFile();
        for(ApplicationDir applicationDir : ApplicationDir.values()) {
            Assertions.assertEquals(xdgDir, applicationDir.get(APPLICATION, false, xdgDir));
        }
    }

    @Test
    public void testConfiguredHomeOverridesXdgDir() {
        File xdgDir = tempDir.resolve("configured").resolve("sparrow").toFile();

        System.setProperty(HOME_PROPERTY, "/configured/home");
        try {
            for(ApplicationDir applicationDir : ApplicationDir.values()) {
                Assertions.assertEquals(new File("/configured/home"), applicationDir.get(APPLICATION, false, xdgDir));
                //The rendezvous between instances must ignore a configured home, but must still follow a migrated category
                Assertions.assertEquals(xdgDir, applicationDir.get(APPLICATION, true, xdgDir));
                Assertions.assertEquals(ApplicationDir.getDefaultDir(APPLICATION), applicationDir.get(APPLICATION, true, null));
            }
        } finally {
            System.clearProperty(HOME_PROPERTY);
        }
    }

    @Test
    public void testXdgDirInUseRequiresExistingDirectory() {
        File missing = tempDir.resolve("missing").resolve("sparrow").toFile();
        Assertions.assertNull(ApplicationDir.DATA.getXdgDirInUse("MissingApp", missing));

        File existing = tempDir.resolve("existing").resolve("sparrow").toFile();
        Assertions.assertTrue(existing.mkdirs());
        Assertions.assertEquals(existing, ApplicationDir.DATA.getXdgDirInUse("ExistingApp", existing));
    }

    @Test
    public void testXdgDirInUseRejectsRegularFile() throws IOException {
        File regularFile = tempDir.resolve("regular").resolve("sparrow").toFile();
        Assertions.assertTrue(regularFile.getParentFile().mkdirs());
        Assertions.assertTrue(regularFile.createNewFile());
        Assertions.assertNull(ApplicationDir.DATA.getXdgDirInUse("RegularFileApp", regularFile));
    }

    @Test
    public void testXdgDirInUseIsPinnedOnceCreated() {
        File xdgDir = tempDir.resolve("created").resolve("sparrow").toFile();
        Assertions.assertNull(ApplicationDir.DATA.getXdgDirInUse("CreatedApp", xdgDir));

        //Creating the directory while the application runs must not move an already resolved category
        Assertions.assertTrue(xdgDir.mkdirs());
        Assertions.assertNull(ApplicationDir.DATA.getXdgDirInUse("CreatedApp", xdgDir));
    }

    @Test
    public void testXdgDirInUseIsPinnedOnceDeleted() {
        File xdgDir = tempDir.resolve("deleted").resolve("sparrow").toFile();
        Assertions.assertTrue(xdgDir.mkdirs());
        Assertions.assertEquals(xdgDir, ApplicationDir.DATA.getXdgDirInUse("DeletedApp", xdgDir));

        Assertions.assertTrue(xdgDir.delete());
        Assertions.assertEquals(xdgDir, ApplicationDir.DATA.getXdgDirInUse("DeletedApp", xdgDir));
    }

    @Test
    public void testXdgDirInUseIsPinnedPerCategory() {
        File xdgDir = tempDir.resolve("category").resolve("sparrow").toFile();
        Assertions.assertNull(ApplicationDir.DATA.getXdgDirInUse("CategoryApp", xdgDir));

        //Categories are resolved independently, so one being pinned must not pin another
        Assertions.assertTrue(xdgDir.mkdirs());
        Assertions.assertEquals(xdgDir, ApplicationDir.CONFIG.getXdgDirInUse("CategoryApp", xdgDir));
    }
}
