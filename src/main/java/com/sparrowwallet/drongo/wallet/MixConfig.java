package com.sparrowwallet.drongo.wallet;

import java.io.File;

public class MixConfig extends Persistable {
    private String scode;
    private Boolean mixOnStartup;
    private File mixToWalletFile;
    private String mixToWalletName;
    private Integer minMixes;

    public MixConfig() {
    }

    public MixConfig(String scode, Boolean mixOnStartup, File mixToWalletFile, String mixToWalletName, Integer minMixes) {
        this.scode = scode;
        this.mixOnStartup = mixOnStartup;
        this.mixToWalletFile = mixToWalletFile;
        this.mixToWalletName = mixToWalletName;
        this.minMixes = minMixes;
    }

    public String getScode() {
        return scode;
    }

    public void setScode(String scode) {
        this.scode = scode;
    }

    public Boolean getMixOnStartup() {
        return mixOnStartup;
    }

    public void setMixOnStartup(Boolean mixOnStartup) {
        this.mixOnStartup = mixOnStartup;
    }

    public File getMixToWalletFile() {
        return mixToWalletFile;
    }

    public void setMixToWalletFile(File mixToWalletFile) {
        this.mixToWalletFile = mixToWalletFile;
    }

    public String getMixToWalletName() {
        return mixToWalletName;
    }

    public void setMixToWalletName(String mixToWalletName) {
        this.mixToWalletName = mixToWalletName;
    }

    public Integer getMinMixes() {
        return minMixes;
    }

    public void setMinMixes(Integer minMixes) {
        this.minMixes = minMixes;
    }

    public MixConfig copy() {
        return new MixConfig(scode, mixOnStartup, mixToWalletFile, mixToWalletName, minMixes);
    }
}
