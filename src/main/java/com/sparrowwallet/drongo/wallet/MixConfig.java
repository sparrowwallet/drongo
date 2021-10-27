package com.sparrowwallet.drongo.wallet;

import java.io.File;

public class MixConfig extends Persistable {
    private String scode;
    private Boolean mixOnStartup;
    private String indexRange;
    private File mixToWalletFile;
    private String mixToWalletName;
    private Integer minMixes;
    private int receiveIndex;
    private int changeIndex;

    public MixConfig() {
    }

    public MixConfig(String scode, Boolean mixOnStartup, String indexRange, File mixToWalletFile, String mixToWalletName, Integer minMixes, int receiveIndex, int changeIndex) {
        this.scode = scode;
        this.mixOnStartup = mixOnStartup;
        this.indexRange = indexRange;
        this.mixToWalletFile = mixToWalletFile;
        this.mixToWalletName = mixToWalletName;
        this.minMixes = minMixes;
        this.receiveIndex = receiveIndex;
        this.changeIndex = changeIndex;
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

    public String getIndexRange() {
        return indexRange;
    }

    public void setIndexRange(String indexRange) {
        this.indexRange = indexRange;
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

    public int getReceiveIndex() {
        return receiveIndex;
    }

    public void setReceiveIndex(int receiveIndex) {
        this.receiveIndex = receiveIndex;
    }

    public int getChangeIndex() {
        return changeIndex;
    }

    public void setChangeIndex(int changeIndex) {
        this.changeIndex = changeIndex;
    }

    public MixConfig copy() {
        return new MixConfig(scode, mixOnStartup, indexRange, mixToWalletFile, mixToWalletName, minMixes, receiveIndex, changeIndex);
    }
}
