package com.sparrowwallet.drongo.wallet.slip39;

import com.sparrowwallet.drongo.wallet.MnemonicException;

import java.util.*;

public class ShareGroup {
    private final Set<Share> shares;

    public ShareGroup() {
        this.shares = new HashSet<>();
    }

    public Iterator<Share> iterator() {
        return this.shares.iterator();
    }

    public int size() {
        return this.shares.size();
    }

    public boolean isEmpty() {
        return this.shares.isEmpty();
    }

    public boolean contains(Share share) {
        return this.shares.contains(share);
    }

    public void add(Share share) throws MnemonicException {
        if(!this.shares.isEmpty() && !this.getGroupParameters().equals(share.getGroupParameters())) {
            throw new MnemonicException("Invalid mnemonic", "Invalid set of mnemonics, group parameters don't match.");
        }
        this.shares.add(share);
    }

    public List<RawShare> toRawShares() {
        List<RawShare> rawShares = new ArrayList<>();
        for(Share s : this.shares) {
            rawShares.add(new RawShare(s.getIndex(), s.getValue()));
        }
        return rawShares;
    }

    public ShareGroup getMinimalGroup() {
        ShareGroup group = new ShareGroup();
        int threshold = this.getMemberThreshold();
        Iterator<Share> iterator = this.shares.iterator();
        while(group.shares.size() < threshold && iterator.hasNext()) {
            group.shares.add(iterator.next());
        }
        return group;
    }

    public Share.CommonParameters getCommonParameters() {
        return this.shares.iterator().next().getCommonParameters();
    }

    public Share.GroupParameters getGroupParameters() {
        return this.shares.iterator().next().getGroupParameters();
    }

    public int getMemberThreshold() {
        return this.shares.iterator().next().getMemberThreshold();
    }

    public boolean isComplete() {
        return !this.shares.isEmpty() && this.shares.size() >= this.getMemberThreshold();
    }
}
