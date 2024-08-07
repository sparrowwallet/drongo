package com.sparrowwallet.drongo.wallet.slip39;

import com.sparrowwallet.drongo.wallet.MnemonicException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.sparrowwallet.drongo.wallet.slip39.Share.GROUP_PREFIX_LENGTH_WORDS;

public class RecoveryState {
    private static final int UNDETERMINED = -1;

    private Share lastShare;
    private final Map<Integer, ShareGroup> groups;
    private Share.CommonParameters parameters;

    public RecoveryState() {
        this.lastShare = null;
        this.groups = new HashMap<>();
        this.parameters = null;
    }

    public String groupPrefix(int groupIndex) {
        if(lastShare == null) {
            throw new IllegalStateException("Add at least one share first");
        }

        Share fakeShare = lastShare.withGroupIndex(groupIndex);
        return String.join(" ", fakeShare.getWords().subList(0, GROUP_PREFIX_LENGTH_WORDS));
    }

    public int[] groupStatus(int groupIndex) {
        ShareGroup group = groups.getOrDefault(groupIndex, new ShareGroup());
        if(group.isEmpty()) {
            return new int[]{0, UNDETERMINED};
        }

        return new int[]{group.size(), group.getMemberThreshold()};
    }

    public boolean groupIsComplete(int groupIndex) {
        ShareGroup group = groups.getOrDefault(groupIndex, new ShareGroup());
        return group.isComplete();
    }

    public int groupsComplete() {
        if(parameters == null) {
            return 0;
        }

        int completeCount = 0;
        for(int i = 0; i < parameters.groupCount(); i++) {
            if(groupIsComplete(i)) {
                completeCount++;
            }
        }
        return completeCount;
    }

    public boolean isComplete() {
        if(parameters == null) {
            return false;
        }
        return groupsComplete() >= parameters.groupThreshold();
    }

    public boolean matches(Share share) {
        if(parameters == null) {
            return true;
        }
        return share.getCommonParameters().equals(parameters);
    }

    public boolean addShare(Share share) throws MnemonicException {
        if(!matches(share)) {
            throw new MnemonicException("Not in current set", "This mnemonic is not part of the current set");
        }
        groups.computeIfAbsent(share.getGroupIndex(), k -> new ShareGroup()).add(share);
        lastShare = share;
        if(parameters == null) {
            parameters = share.getCommonParameters();
        }
        return true;
    }

    public boolean contains(Share share) {
        if(!matches(share)) {
            return false;
        }

        if(groups.isEmpty()) {
            return false;
        }

        ShareGroup group = groups.getOrDefault(share.getGroupIndex(), new ShareGroup());
        return group.contains(share);
    }

    public byte[] recover(byte[] passphrase) throws MnemonicException {
        Map<Integer, ShareGroup> reducedGroups = new HashMap<>();
        for(Map.Entry<Integer, ShareGroup> entry : groups.entrySet()) {
            int groupIndex = entry.getKey();
            ShareGroup group = entry.getValue();
            if(group.isComplete()) {
                reducedGroups.put(groupIndex, group.getMinimalGroup());
            }

            if(reducedGroups.size() >= parameters.groupThreshold()) {
                break;
            }
        }

        EncryptedMasterSecret encryptedMasterSecret = Shamir.recoverEms(reducedGroups);
        return encryptedMasterSecret.decrypt(passphrase);
    }

    public String getStatus() {
        StringBuilder status = new StringBuilder();
        if(parameters.groupCount() > 1) {
            status.append("Completed ").append(groupsComplete()).append(" of ").append(parameters.groupThreshold()).append(" groups needed:\n");
        }

        for(int i = 0; i < parameters.groupCount(); i++) {
            status.append(getGroupStatus(i));
            if(i < parameters.groupCount() - 1) {
                status.append("\n");
            }
        }

        return status.toString();
    }

    public String getGroupStatus(int index) {
        int[] groupStatus = groupStatus(index);
        int groupSize = groupStatus[0];
        int groupThreshold = groupStatus[1];
        String groupPrefix = groupPrefix(index);

        if(groupSize == 0) {
            return groupSize + " shares from group " + groupPrefix;
        } else {
            return groupSize + " of " + groupThreshold + " shares needed from group " + groupPrefix;
        }
    }

    public String getShortStatus() {
        StringBuilder status = new StringBuilder();
        if(parameters.groupCount() > 1) {
            status.append(groupsComplete()).append(" of ").append(parameters.groupThreshold()).append(" groups, ");
        }

        List<String> groupStatuses = new ArrayList<>();
        for(int i = 0; i < parameters.groupCount(); i++) {
            String groupStatus = getGroupShortStatus(i);
            if(!groupStatus.isEmpty()) {
                groupStatuses.add(groupStatus);
            }
        }
        status.append(String.join(", ", groupStatuses));

        return status.toString();
    }

    public String getGroupShortStatus(int index) {
        int[] groupStatus = groupStatus(index);
        int groupSize = groupStatus[0];
        int groupThreshold = groupStatus[1];

        if(groupSize > 0) {
            return groupSize + " of " + groupThreshold + " shares";
        }

        return "";
    }
}
