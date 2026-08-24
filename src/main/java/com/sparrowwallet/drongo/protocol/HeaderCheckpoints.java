package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * The per-network list of pinned header hashes compiled into the binary and extended every feature release: the hash of the last
 * header of each difficulty period from genesis, with the compact target the following period is required to use.
 * The last entry anchors forward header validation; earlier entries verify historical headers by hash linkage.
 */
public class HeaderCheckpoints {
    private static final String CHECKPOINTS_RESOURCE_DIR = "/checkpoints/";
    private static final Map<Network, HeaderCheckpoints> NETWORK_CHECKPOINTS = new EnumMap<>(Network.class);

    private final Network network;
    private final List<Sha256Hash> hashes;      //index k = hash at height 2016k + 2015
    private final List<Long> bits;              //index k = required compact target for period k + 1

    private HeaderCheckpoints(Network network, List<Sha256Hash> hashes, List<Long> bits) {
        this.network = network;
        this.hashes = hashes;
        this.bits = bits;
    }

    /** The checkpoints for the given network, parsed from its resource on first use and cached. Regtest has none. */
    public static synchronized HeaderCheckpoints get(Network network) {
        return NETWORK_CHECKPOINTS.computeIfAbsent(network, HeaderCheckpoints::load);
    }

    private static HeaderCheckpoints load(Network network) {
        if(network == Network.REGTEST) {
            return new HeaderCheckpoints(network, Collections.emptyList(), Collections.emptyList());
        }

        String resource = CHECKPOINTS_RESOURCE_DIR + network.getName() + ".txt";
        try(InputStream inputStream = HeaderCheckpoints.class.getResourceAsStream(resource)) {
            if(inputStream == null) {
                throw new IllegalStateException("No checkpoints resource at " + resource);
            }

            return parse(network, inputStream);
        } catch(IOException e) {
            throw new UncheckedIOException("Failed to read " + resource, e);
        }
    }

    static HeaderCheckpoints parse(Network network, InputStream inputStream) throws IOException {
        List<Sha256Hash> hashes = new ArrayList<>();
        List<Long> bits = new ArrayList<>();
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        String line;
        int lineNumber = 0;
        while((line = reader.readLine()) != null) {
            lineNumber++;
            if(line.isBlank()) {
                continue;
            }

            String[] parts = line.split(" ");
            if(parts.length != 2 || parts[0].length() != 64 || parts[1].length() != 8) {
                throw new IllegalStateException("Malformed checkpoint for " + network + " at line " + lineNumber + ": " + line);
            }

            long compactBits;
            Sha256Hash hash;
            try {
                hash = Sha256Hash.wrap(parts[0]);
                compactBits = Long.parseLong(parts[1], 16);
            } catch(IllegalArgumentException | ProtocolException e) {
                throw new IllegalStateException("Malformed checkpoint for " + network + " at line " + lineNumber + ": " + line, e);
            }

            BigInteger target = Utils.decodeCompactBits(compactBits);
            if(target.signum() <= 0 || Utils.encodeCompactBits(target) != compactBits) {
                throw new IllegalStateException("Checkpoint for " + network + " at line " + lineNumber + " has a target that does not round trip: " + parts[1]);
            }

            hashes.add(hash);
            bits.add(compactBits);
        }

        if(hashes.isEmpty()) {
            throw new IllegalStateException("No checkpoints found for " + network);
        }

        return new HeaderCheckpoints(network, List.copyOf(hashes), List.copyOf(bits));
    }

    /** The height of the last pinned header, or 0 for regtest (genesis, whose hash is Network.getGenesisHash()). */
    public int getMaxHeight() {
        return hashes.isEmpty() ? 0 : hashes.size() * HeaderChainState.RETARGET_INTERVAL - 1;
    }

    /** The pinned hash at a pinned height. */
    public Sha256Hash getHash(int height) {
        if(hashes.isEmpty()) {
            if(height != 0) {
                throw new IllegalArgumentException("Height " + height + " is not a pinned height");
            }

            return network.getGenesisHash();
        }
        if(height < 0 || height > getMaxHeight() || (height + 1) % HeaderChainState.RETARGET_INTERVAL != 0) {
            throw new IllegalArgumentException("Height " + height + " is not a pinned height");
        }

        return hashes.get((height + 1) / HeaderChainState.RETARGET_INTERVAL - 1);
    }

    /** The smallest pinned height greater than or equal to the given height. */
    public int getPinnedHeightAtOrAbove(int height) {
        if(height < 0 || height > getMaxHeight()) {
            throw new IllegalArgumentException("Height " + height + " has no pinned height at or above it");
        }
        if(hashes.isEmpty()) {
            return 0;
        }

        return (height / HeaderChainState.RETARGET_INTERVAL) * HeaderChainState.RETARGET_INTERVAL + HeaderChainState.RETARGET_INTERVAL - 1;
    }

    /** The compact target required of the header immediately following the given pinned height. */
    public long getBitsAfter(int pinnedHeight) {
        if(hashes.isEmpty()) {
            if(pinnedHeight != 0) {
                throw new IllegalArgumentException("Height " + pinnedHeight + " is not a pinned height");
            }

            return network.getGenesisHeader().getDifficultyTarget();
        }
        if(pinnedHeight < 0 || pinnedHeight > getMaxHeight() || (pinnedHeight + 1) % HeaderChainState.RETARGET_INTERVAL != 0) {
            throw new IllegalArgumentException("Height " + pinnedHeight + " is not a pinned height");
        }

        return bits.get((pinnedHeight + 1) / HeaderChainState.RETARGET_INTERVAL - 1);
    }

    /** A chain state anchored at the last pinned header, ready to accept the header immediately above it. */
    public HeaderChainState newChainState() {
        int maxHeight = getMaxHeight();

        return new HeaderChainState(maxHeight, getHash(maxHeight), getBitsAfter(maxHeight));
    }
}
