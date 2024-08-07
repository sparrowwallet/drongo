package com.sparrowwallet.drongo.wallet.slip39;

import com.sparrowwallet.drongo.wallet.MnemonicException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

public class ShareTest {
    @Test
    public void test1of1() throws MnemonicException {
        String mnemonic = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";
        Share share = Share.fromMnemonic(mnemonic);
        Assertions.assertEquals(7945, share.getCommonParameters().identifier());
        Assertions.assertFalse(share.getCommonParameters().extendable());
        Assertions.assertEquals(0, share.getGroupParameters().iterationExponent());
        Assertions.assertEquals(1, share.getGroupParameters().groupCount());
        Assertions.assertEquals(1, share.getGroupParameters().groupThreshold());
        Assertions.assertEquals(0, share.getGroupParameters().groupIndex());
        Assertions.assertEquals(1, share.getGroupParameters().memberThreshold());
        Assertions.assertEquals(0, share.getIndex());
        Assertions.assertEquals("11bc609d21747c49ba78c0701293e417", HexFormat.of().formatHex(share.getValue()));

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(share);
        byte[] secret = recoveryState.recover(getPassphrase());
        Assertions.assertEquals("bb54aac4b89dc868ba37d9cc21b2cece", HexFormat.of().formatHex(secret));

        List<List<String>> generated = Shamir.generateMnemonics(share.getGroupParameters().groupThreshold(),
                List.of(new GroupParams(1, 1)),
                secret, getPassphrase(), share.getCommonParameters().extendable(), share.getGroupParameters().iterationExponent());
        Assertions.assertEquals(1, generated.size());
        Assertions.assertEquals(1, generated.get(0).size());
        String generatedMnemonic = String.join(" ", generated.get(0).get(0));

        Share generatedShare = Share.fromMnemonic(generatedMnemonic);
        Assertions.assertFalse(generatedShare.getCommonParameters().extendable());
        Assertions.assertEquals(0, generatedShare.getGroupParameters().iterationExponent());
        Assertions.assertEquals(1, generatedShare.getGroupParameters().groupCount());
        Assertions.assertEquals(1, generatedShare.getGroupParameters().groupThreshold());
        Assertions.assertEquals(0, generatedShare.getGroupParameters().groupIndex());
        Assertions.assertEquals(1, generatedShare.getGroupParameters().memberThreshold());
        Assertions.assertEquals(0, generatedShare.getIndex());

        RecoveryState generatedRecoveryState = new RecoveryState();
        generatedRecoveryState.addShare(generatedShare);
        byte[] generatedSecret = generatedRecoveryState.recover(getPassphrase());
        Assertions.assertEquals("bb54aac4b89dc868ba37d9cc21b2cece", HexFormat.of().formatHex(generatedSecret));
    }

    private static byte[] getPassphrase() {
        return "TREZOR".getBytes(StandardCharsets.US_ASCII);
    }

    @Test
    public void testInvalidChecksum() {
        String mnemonic = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney";
        MnemonicException exception = Assertions.assertThrows(MnemonicException.class, () -> Share.fromMnemonic(mnemonic));
    }

    @Test
    public void testInvalidPadding() {
        String mnemonic = "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness";
        MnemonicException exception = Assertions.assertThrows(MnemonicException.class, () -> Share.fromMnemonic(mnemonic));
    }

    @Test
    public void test2of3() throws MnemonicException {
        String mnemonic1 = "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed";
        Share share1 = Share.fromMnemonic(mnemonic1);

        Assertions.assertEquals(25653, share1.getCommonParameters().identifier());
        Assertions.assertFalse(share1.getCommonParameters().extendable());
        Assertions.assertEquals(2, share1.getGroupParameters().iterationExponent());
        Assertions.assertEquals(1, share1.getGroupParameters().groupCount());
        Assertions.assertEquals(1, share1.getGroupParameters().groupThreshold());
        Assertions.assertEquals(0, share1.getGroupParameters().groupIndex());
        Assertions.assertEquals(2, share1.getGroupParameters().memberThreshold());
        Assertions.assertEquals(2, share1.getIndex());
        Assertions.assertEquals("08fb14b66e692e25dfe2edf53289ed62", HexFormat.of().formatHex(share1.getValue()));

        String mnemonic2 = "shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking";
        Share share2 = Share.fromMnemonic(mnemonic2);

        Assertions.assertEquals(25653, share2.getCommonParameters().identifier());
        Assertions.assertFalse(share2.getCommonParameters().extendable());
        Assertions.assertEquals(2, share2.getGroupParameters().iterationExponent());
        Assertions.assertEquals(1, share2.getGroupParameters().groupCount());
        Assertions.assertEquals(1, share2.getGroupParameters().groupThreshold());
        Assertions.assertEquals(0, share2.getGroupParameters().groupIndex());
        Assertions.assertEquals(2, share2.getGroupParameters().memberThreshold());
        Assertions.assertEquals(0, share2.getIndex());
        Assertions.assertEquals("06ab48fef4bedc8ce58baeef0a73f76e", HexFormat.of().formatHex(share2.getValue()));

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(share1);
        recoveryState.addShare(share2);
        byte[] secret = recoveryState.recover(getPassphrase());
        Assertions.assertEquals("b43ceb7e57a0ea8766221624d01b0864", HexFormat.of().formatHex(secret));

        List<List<String>> generated = Shamir.generateMnemonics(share1.getGroupParameters().groupThreshold(),
                List.of(new GroupParams(2, 3)),
                secret, getPassphrase(), share1.getCommonParameters().extendable(), share1.getGroupParameters().iterationExponent());
        Assertions.assertEquals(1, generated.size());
        Assertions.assertEquals(3, generated.get(0).size());
        String generatedMnemonic1 = String.join(" ", generated.get(0).get(0));

        Share generatedShare1 = Share.fromMnemonic(generatedMnemonic1);
        Assertions.assertFalse(generatedShare1.getCommonParameters().extendable());
        Assertions.assertEquals(2, generatedShare1.getGroupParameters().iterationExponent());
        Assertions.assertEquals(1, generatedShare1.getGroupParameters().groupCount());
        Assertions.assertEquals(1, generatedShare1.getGroupParameters().groupThreshold());
        Assertions.assertEquals(0, generatedShare1.getGroupParameters().groupIndex());
        Assertions.assertEquals(2, generatedShare1.getGroupParameters().memberThreshold());
        Assertions.assertEquals(0, generatedShare1.getIndex());

        String generatedMnemonic2 = String.join(" ", generated.get(0).get(1));
        Share generatedShare2 = Share.fromMnemonic(generatedMnemonic2);
        Assertions.assertFalse(generatedShare1.getCommonParameters().extendable());
        Assertions.assertEquals(2, generatedShare2.getGroupParameters().iterationExponent());
        Assertions.assertEquals(1, generatedShare2.getGroupParameters().groupCount());
        Assertions.assertEquals(1, generatedShare2.getGroupParameters().groupThreshold());
        Assertions.assertEquals(0, generatedShare2.getGroupParameters().groupIndex());
        Assertions.assertEquals(2, generatedShare2.getGroupParameters().memberThreshold());
        Assertions.assertEquals(1, generatedShare2.getIndex());

        RecoveryState generatedRecoveryState = new RecoveryState();
        generatedRecoveryState.addShare(generatedShare1);
        generatedRecoveryState.addShare(generatedShare2);
        byte[] generatedSecret = generatedRecoveryState.recover(getPassphrase());
        Assertions.assertEquals("b43ceb7e57a0ea8766221624d01b0864", HexFormat.of().formatHex(generatedSecret));
    }

    @Test
    public void testDifferentIds() throws MnemonicException {
        String mnemonic1 = "adequate smoking academic acid debut wine petition glen cluster slow rhyme slow simple epidemic rumor junk tracks treat olympic tolerate";
        String mnemonic2 = "adequate stay academic agency agency formal party ting frequent learn upstairs remember smear leaf damage anatomy ladle market hush corner";

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(Share.fromMnemonic(mnemonic1));
        Assertions.assertThrows(MnemonicException.class, () -> recoveryState.addShare(Share.fromMnemonic(mnemonic2)));
    }

    @Test
    public void testDifferentIterationExps() throws MnemonicException {
        String mnemonic1 = "peasant leaves academic acid desert exact olympic math alive axle trial tackle drug deny decent smear dominant desert bucket remind";
        String mnemonic2 = "peasant leader academic agency cultural blessing percent network envelope medal junk primary human pumps jacket fragment payroll ticket evoke voice";

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(Share.fromMnemonic(mnemonic1));
        Assertions.assertThrows(MnemonicException.class, () -> recoveryState.addShare(Share.fromMnemonic(mnemonic2)));
    }

    @Test
    public void testMismatchGroupThresholds() throws MnemonicException {
        String mnemonic1 = "liberty category beard echo animal fawn temple briefing math username various wolf aviation fancy visual holy thunder yelp helpful payment";
        String mnemonic2 = "liberty category beard email beyond should fancy romp founder easel pink holy hairy romp loyalty material victim owner toxic custody";
        String mnemonic3 = "liberty category academic easy being hazard crush diminish oral lizard reaction cluster force dilemma deploy force club veteran expect photo";

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(Share.fromMnemonic(mnemonic1));
        recoveryState.addShare(Share.fromMnemonic(mnemonic2));
        Assertions.assertThrows(MnemonicException.class, () -> recoveryState.addShare(Share.fromMnemonic(mnemonic3)));
    }

    @Test
    public void testMismatchGroupCounts() throws MnemonicException {
        String mnemonic1 = "average senior academic leaf broken teacher expect surface hour capture obesity desire negative dynamic dominant pistol mineral mailman iris aide";
        String mnemonic2 = "average senior academic agency curious pants blimp spew clothes slice script dress wrap firm shaft regular slavery negative theater roster";

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(Share.fromMnemonic(mnemonic1));
        Assertions.assertThrows(MnemonicException.class, () -> recoveryState.addShare(Share.fromMnemonic(mnemonic2)));
    }

    @Test
    public void testGreaterGroupThresholds() throws MnemonicException {
        String mnemonic1 = "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome";

        RecoveryState recoveryState = new RecoveryState();
        Assertions.assertThrows(MnemonicException.class, () -> recoveryState.addShare(Share.fromMnemonic(mnemonic1)));
    }

    @Test
    public void testDuplicateIndices() throws MnemonicException {
        String mnemonic1 = "device stay academic always dive coal antenna adult black exceed stadium herald advance soldier busy dryer daughter evaluate minister laser";
        String mnemonic2 = "device stay academic always dwarf afraid robin gravity crunch adjust soul branch walnut coastal dream costume scholar mortgage mountain pumps";

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(Share.fromMnemonic(mnemonic1));
        recoveryState.addShare(Share.fromMnemonic(mnemonic2));
        Assertions.assertThrows(MnemonicException.class, () -> recoveryState.recover(getPassphrase()));
    }

    @Test
    public void mismatchMemberThresholds() throws MnemonicException {
        String mnemonic1 = "hour painting academic academic device formal evoke guitar random modern justice filter withdraw trouble identify mailman insect general cover oven";
        String mnemonic2 = "hour painting academic agency artist again daisy capital beaver fiber much enjoy suitable symbolic identify photo editor romp float echo";

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(Share.fromMnemonic(mnemonic1));
        Assertions.assertThrows(MnemonicException.class, () -> recoveryState.addShare(Share.fromMnemonic(mnemonic2)));
    }

    @Test
    public void invalidDigest() throws MnemonicException {
        String mnemonic1 = "guilt walnut academic acid deliver remove equip listen vampire tactics nylon rhythm failure husband fatigue alive blind enemy teaspoon rebound";
        String mnemonic2 = "guilt walnut academic agency brave hamster hobo declare herd taste alpha slim criminal mild arcade formal romp branch pink ambition";

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(Share.fromMnemonic(mnemonic1));
        recoveryState.addShare(Share.fromMnemonic(mnemonic2));
        Assertions.assertThrows(MnemonicException.class, () -> recoveryState.recover(getPassphrase()));
    }

    @Test
    public void testInsufficientGroupNumber1() throws MnemonicException {
        String mnemonic1 = "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice";

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(Share.fromMnemonic(mnemonic1));
        Assertions.assertThrows(MnemonicException.class, () -> recoveryState.recover(getPassphrase()));
    }

    @Test
    public void testInsufficientGroupNumber2() throws MnemonicException {
        String mnemonic1 = "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join";
        String mnemonic2 = "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter";

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(Share.fromMnemonic(mnemonic1));
        recoveryState.addShare(Share.fromMnemonic(mnemonic2));
        Assertions.assertThrows(MnemonicException.class, () -> recoveryState.recover(getPassphrase()));
    }

    @Test
    public void test2of3with256() throws MnemonicException {
        String mnemonic1 = "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap";
        Share share1 = Share.fromMnemonic(mnemonic1);

        String mnemonic2 = "humidity disease academic agency actress jacket gross physics cylinder solution fake mortgage benefit public busy prepare sharp friar change work slow purchase ruler again tricycle involve viral wireless mixture anatomy desert cargo upgrade";
        Share share2 = Share.fromMnemonic(mnemonic2);

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(Share.fromMnemonic(mnemonic1));
        recoveryState.addShare(Share.fromMnemonic(mnemonic2));
        byte[] secret = recoveryState.recover(getPassphrase());
        Assertions.assertEquals("c938b319067687e990e05e0da0ecce1278f75ff58d9853f19dcaeed5de104aae", HexFormat.of().formatHex(secret));
    }

    @Test
    public void testInvalidMnemonicLength() throws MnemonicException {
        String mnemonic = "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder";

        Assertions.assertThrows(MnemonicException.class, () -> Share.fromMnemonic(mnemonic));
    }

    @Test
    public void testInvalidMasterSecret() throws MnemonicException {
        String mnemonic = "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter";

        Assertions.assertThrows(MnemonicException.class, () -> Share.fromMnemonic(mnemonic));
    }

    @Test
    public void testModularArithmetic() throws MnemonicException {
        String mnemonic1 = "herald flea academic cage avoid space trend estate dryer hairy evoke eyebrow improve airline artwork garlic premium duration prevent oven";
        String mnemonic2 = "herald flea academic client blue skunk class goat luxury deny presence impulse graduate clay join blanket bulge survive dish necklace";
        String mnemonic3 = "herald flea academic acne advance fused brother frozen broken game ranked ajar already believe check install theory angry exercise adult";

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(Share.fromMnemonic(mnemonic1));
        recoveryState.addShare(Share.fromMnemonic(mnemonic2));
        recoveryState.addShare(Share.fromMnemonic(mnemonic3));
        byte[] secret = recoveryState.recover(getPassphrase());
        Assertions.assertEquals("ad6f2ad8b59bbbaa01369b9006208d9a", HexFormat.of().formatHex(secret));
    }

    @Test
    public void test1of1extendable() throws MnemonicException {
        String mnemonic = "testify swimming academic academic column loyalty smear include exotic bedroom exotic wrist lobe cover grief golden smart junior estimate learn";
        Share share = Share.fromMnemonic(mnemonic);
        Assertions.assertTrue(share.getCommonParameters().extendable());

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(share);
        byte[] secret = recoveryState.recover(getPassphrase());
        Assertions.assertEquals("1679b4516e0ee5954351d288a838f45e", HexFormat.of().formatHex(secret));
    }

    @Test
    public void test1of1extendable256() throws MnemonicException {
        String mnemonic = "impulse calcium academic academic alcohol sugar lyrics pajamas column facility finance tension extend space birthday rainbow swimming purple syndrome facility trial warn duration snapshot shadow hormone rhyme public spine counter easy hawk album";
        Share share = Share.fromMnemonic(mnemonic);
        Assertions.assertTrue(share.getCommonParameters().extendable());

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(share);
        byte[] secret = recoveryState.recover(getPassphrase());
        Assertions.assertEquals("8340611602fe91af634a5f4608377b5235fa2d757c51d720c0c7656249a3035f", HexFormat.of().formatHex(secret));
    }

    @Test
    public void test2of3extendable() throws MnemonicException {
        String mnemonic1 = "enemy favorite academic acid cowboy phrase havoc level response walnut budget painting inside trash adjust froth kitchen learn tidy punish";
        Share share1 = Share.fromMnemonic(mnemonic1);
        Assertions.assertTrue(share1.getCommonParameters().extendable());

        String mnemonic2 = "enemy favorite academic always academic sniff script carpet romp kind promise scatter center unfair training emphasis evening belong fake enforce";
        Share share2 = Share.fromMnemonic(mnemonic2);
        Assertions.assertTrue(share2.getCommonParameters().extendable());

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(share1);
        recoveryState.addShare(share2);
        byte[] secret = recoveryState.recover(getPassphrase());
        Assertions.assertEquals("48b1a4b80b8c209ad42c33672bdaa428", HexFormat.of().formatHex(secret));
    }

    @Test
    public void test2of3extendable256() throws MnemonicException {
        String mnemonic1 = "western apart academic always artist resident briefing sugar woman oven coding club ajar merit pecan answer prisoner artist fraction amount desktop mild false necklace muscle photo wealthy alpha category unwrap spew losing making";
        Share share1 = Share.fromMnemonic(mnemonic1);
        Assertions.assertTrue(share1.getCommonParameters().extendable());

        String mnemonic2 = "western apart academic acid answer ancient auction flip image penalty oasis beaver multiple thunder problem switch alive heat inherit superior teaspoon explain blanket pencil numb lend punish endless aunt garlic humidity kidney observe";
        Share share2 = Share.fromMnemonic(mnemonic2);
        Assertions.assertTrue(share2.getCommonParameters().extendable());

        RecoveryState recoveryState = new RecoveryState();
        recoveryState.addShare(share1);
        recoveryState.addShare(share2);
        byte[] secret = recoveryState.recover(getPassphrase());
        Assertions.assertEquals("8dc652d6d6cd370d8c963141f6d79ba440300f25c467302c1d966bff8f62300d", HexFormat.of().formatHex(secret));
    }
}
