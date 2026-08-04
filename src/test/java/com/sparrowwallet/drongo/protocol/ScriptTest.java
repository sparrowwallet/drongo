package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ScriptTest {
    @Test
    public void removeCodeSeparators() {
        //OP_DUP OP_HASH160 <20 bytes> OP_CODESEPARATOR OP_EQUALVERIFY OP_CHECKSIG
        byte[] script = Utils.hexToBytes("76a914e8df018c7e326cc253faac7e46cdc51e68542c42ab88ac");
        byte[] expected = Utils.hexToBytes("76a914e8df018c7e326cc253faac7e46cdc51e68542c4288ac");
        Assertions.assertArrayEquals(expected, Script.removeAllInstancesOfOp(script, ScriptOpCodes.OP_CODESEPARATOR));
    }

    @Test
    public void removeNothingFromValidScript() {
        //A script with no OP_CODESEPARATOR must come back byte for byte
        byte[] script = Utils.hexToBytes("76a914e8df018c7e326cc253faac7e46cdc51e68542c4288ac");
        Assertions.assertArrayEquals(script, Script.removeAllInstancesOfOp(script, ScriptOpCodes.OP_CODESEPARATOR));
    }

    @Test
    public void removeCodeSeparatorFromLargePush() {
        //OP_PUSHDATA1 of 0xab bytes, all of them OP_CODESEPARATOR - the push data must not be touched
        StringBuilder pushData = new StringBuilder();
        for(int i = 0; i < 0xab; i++) {
            pushData.append("ab");
        }
        byte[] script = Utils.hexToBytes("ab4cab" + pushData + "ab");
        byte[] expected = Utils.hexToBytes("4cab" + pushData);
        Assertions.assertArrayEquals(expected, Script.removeAllInstancesOfOp(script, ScriptOpCodes.OP_CODESEPARATOR));
    }

    @Test
    public void pushDataExactlyFillsScript() {
        //A push whose data ends exactly at the end of the script is well formed and must survive the bound
        assertRemovalRemovesLeadingSeparator("ab0405060708");
        assertRemovalRemovesLeadingSeparator("ab4c0405060708");
        assertRemovalRemovesLeadingSeparator("ab4d040005060708");
        assertRemovalRemovesLeadingSeparator("ab4e0400000005060708");
        //A zero length push sitting at the very end is also well formed
        assertRemovalRemovesLeadingSeparator("ab884c00");
        assertRemovalRemovesLeadingSeparator("ab884d0000");
        assertRemovalRemovesLeadingSeparator("ab884e00000000");
    }

    @Test
    public void codeSeparatorFollowingPush() {
        //A trailing OP_CODESEPARATOR checks that the scan resumes past the push data rather than inside it, so the
        //separator is still seen and removed. Appending it moves the push off the bound, which is covered below.
        assertRemoval("ab0405060708ab", "0405060708");
        assertRemoval("ab4c0405060708ab", "4c0405060708");
        assertRemoval("ab4d040005060708ab", "4d040005060708");
        assertRemoval("ab4e0400000005060708ab", "4e0400000005060708");
        assertRemoval("ab884c00ab", "884c00");
    }

    @Test
    public void pushExactlyFillingScriptIsStillRemoved() {
        //The exact fit cases above cannot fail on their own: emitting a push and copying it verbatim produce the same
        //bytes once it ends the script. Removing that push tells the two apart, as a well formed push is dropped
        //while a fragment held to be unparseable would be preserved. This is Bitcoin Core deleting a signature push.
        assertChunkRemoval("ab050102030405", "050102030405", "ab");
        assertChunkRemoval("ab4c050102030405", "4c050102030405", "ab");
        assertChunkRemoval("ab4d05000102030405", "4d05000102030405", "ab");
        assertChunkRemoval("ab4e050000000102030405", "4e050000000102030405", "ab");
        //A zero length push leaves the length prefix as the last byte of the script
        assertChunkRemoval("ab4c00", "4c00", "ab");
    }

    @Test
    public void truncatedPushDataLengths() {
        //A push length prefix that is cut short leaves an unparseable fragment, which is copied through unchanged
        assertRemovalRemovesLeadingSeparator("ab884c");
        assertRemovalRemovesLeadingSeparator("ab884d01");
        assertRemovalRemovesLeadingSeparator("ab884e010000");
    }

    @Test
    public void truncatedPushData() {
        //A push that claims more data than the script holds is equally unparseable, and must not be zero padded
        assertRemovalRemovesLeadingSeparator("ab88050102");
        assertRemovalRemovesLeadingSeparator("ab884c050102");
        assertRemovalRemovesLeadingSeparator("ab884d05000102");
        assertRemovalRemovesLeadingSeparator("ab884e050000000102");
    }

    @Test
    public void oversizedPushData() {
        //A PUSHDATA4 length of 0xfffffffb overflows a signed int, and previously gave a negative push length
        assertRemovalRemovesLeadingSeparator("ab884efbffffff");
        //A length of 0xffffffff wraps the other way - as an int it is -1, so +4 gave a silently mis-parsed 3 byte push
        assertRemovalRemovesLeadingSeparator("ab884effffffff0102");
    }

    private void assertRemovalRemovesLeadingSeparator(String scriptHex) {
        //Only the leading OP_CODESEPARATOR goes, whether the rest parses or is preserved as an unparseable remainder
        assertRemoval(scriptHex, scriptHex.substring(2));
    }

    private void assertRemoval(String scriptHex, String expectedHex) {
        byte[] script = Utils.hexToBytes(scriptHex);
        byte[] expected = Utils.hexToBytes(expectedHex);
        Assertions.assertArrayEquals(expected, Script.removeAllInstancesOfOp(script, ScriptOpCodes.OP_CODESEPARATOR));
    }

    private void assertChunkRemoval(String scriptHex, String chunkHex, String expectedHex) {
        byte[] script = Utils.hexToBytes(scriptHex);
        byte[] chunk = Utils.hexToBytes(chunkHex);
        byte[] expected = Utils.hexToBytes(expectedHex);
        Assertions.assertArrayEquals(expected, Script.removeAllInstancesOf(script, chunk));
    }
}
