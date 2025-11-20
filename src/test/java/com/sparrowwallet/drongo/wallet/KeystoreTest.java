package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.HDKeyDerivation;
import com.sparrowwallet.drongo.protocol.ScriptType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

public class KeystoreTest {
    @Test
    public void testExtendedPrivateKey() throws MnemonicException {
        Keystore keystore = new Keystore();
        DeterministicSeed seed = new DeterministicSeed("absent essay fox snake vast pumpkin height crouch silent bulb excuse razor", "", 0, DeterministicSeed.Type.BIP39);
        keystore.setSeed(seed);

        Assertions.assertEquals("xprv9s21ZrQH143K3rN5vhm4bKDKsk1PmUK1mzxSMwkVSp2GbomwGmjLaGqrs8Nn9r14jCsfCNWfTR6pAtCsJutUH6QSHX65CePNW3YVyGxqvJa", keystore.getExtendedMasterPrivateKey().toString());
    }

    @Test
    public void testFromSeed() throws MnemonicException {
        ScriptType p2pkh = ScriptType.P2PKH;
        DeterministicSeed seed = new DeterministicSeed("absent essay fox snake vast pumpkin height crouch silent bulb excuse razor", "", 0, DeterministicSeed.Type.BIP39);
        Keystore keystore = Keystore.fromSeed(seed, p2pkh.getDefaultDerivation());

        Assertions.assertEquals("xpub6D9jqMkBdgTqrzTxXVo2w8yZCa7HvzJTybFevJ2StHSxBRhs8dzsVEke9TQ9QjZCKbWZvzbc8iSScBbsCiA11wT28hZmCv3YmjSFEqCLmMn", keystore.getExtendedPublicKey().toString());
    }

    @Test
    void bip32TestVector1() throws MnemonicException {
        byte[] secret = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");

        DeterministicKey key = HDKeyDerivation.createMasterPrivateKey(secret);
        MasterPrivateExtendedKey mpek = new MasterPrivateExtendedKey(key);

        Keystore keystore = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m"));
        Assertions.assertEquals("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", keystore.getExtendedMasterPublicKey().toString());
        Assertions.assertEquals("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", keystore.getExtendedMasterPrivateKey().toString());

        Keystore keystore0h = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0H"));
        Assertions.assertEquals("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", keystore0h.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", keystore0h.getExtendedPrivateKey(false).toString());

        Keystore keystore0h1 = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0H/1"));
        Assertions.assertEquals("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", keystore0h1.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", keystore0h1.getExtendedPrivateKey(false).toString());

        Keystore keystore0h12h = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0H/1/2H"));
        Assertions.assertEquals("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", keystore0h12h.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", keystore0h12h.getExtendedPrivateKey(false).toString());

        Keystore keystore0h12h2 = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0H/1/2H/2"));
        Assertions.assertEquals("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV", keystore0h12h2.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334", keystore0h12h2.getExtendedPrivateKey(false).toString());

        Keystore keystore0h12h21000000000 = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0H/1/2H/2/1000000000"));
        Assertions.assertEquals("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", keystore0h12h21000000000.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", keystore0h12h21000000000.getExtendedPrivateKey(false).toString());
    }

    @Test
    void bip32TestVector2() throws MnemonicException {
        byte[] secret = HexFormat.of().parseHex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

        DeterministicKey key = HDKeyDerivation.createMasterPrivateKey(secret);
        MasterPrivateExtendedKey mpek = new MasterPrivateExtendedKey(key);

        Keystore keystore = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m"));
        Assertions.assertEquals("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB", keystore.getExtendedMasterPublicKey().toString());
        Assertions.assertEquals("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U", keystore.getExtendedMasterPrivateKey().toString());

        Keystore keystore0 = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0"));
        Assertions.assertEquals("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH", keystore0.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt", keystore0.getExtendedPrivateKey(false).toString());

        Keystore keystore1 = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0/2147483647H"));
        Assertions.assertEquals("xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a", keystore1.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9", keystore1.getExtendedPrivateKey(false).toString());

        Keystore keystore2 = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0/2147483647H/1"));
        Assertions.assertEquals("xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon", keystore2.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef", keystore2.getExtendedPrivateKey(false).toString());

        Keystore keystore3 = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0/2147483647H/1/2147483646H"));
        Assertions.assertEquals("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL", keystore3.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc", keystore3.getExtendedPrivateKey(false).toString());

        Keystore keystore4 = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0/2147483647H/1/2147483646H/2"));
        Assertions.assertEquals("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt", keystore4.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", keystore4.getExtendedPrivateKey(false).toString());
    }

    @Test
    void bip32TestVector3() throws MnemonicException {
        byte[] secret = HexFormat.of().parseHex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");

        DeterministicKey key = HDKeyDerivation.createMasterPrivateKey(secret);
        MasterPrivateExtendedKey mpek = new MasterPrivateExtendedKey(key);

        Keystore keystore = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m"));
        Assertions.assertEquals("xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13", keystore.getExtendedMasterPublicKey().toString());
        Assertions.assertEquals("xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6", keystore.getExtendedMasterPrivateKey().toString());

        Keystore keystore0h = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0H"));
        Assertions.assertEquals("xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y", keystore0h.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L", keystore0h.getExtendedPrivateKey(false).toString());
    }

    @Test
    void bip32TestVector4() throws MnemonicException {
        byte[] secret = HexFormat.of().parseHex("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678");

        DeterministicKey key = HDKeyDerivation.createMasterPrivateKey(secret);
        MasterPrivateExtendedKey mpek = new MasterPrivateExtendedKey(key);

        Keystore keystore = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m"));
        Assertions.assertEquals("xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa", keystore.getExtendedMasterPublicKey().toString());
        Assertions.assertEquals("xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv", keystore.getExtendedMasterPrivateKey().toString());

        Keystore keystore0h = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0H"));
        Assertions.assertEquals("xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m", keystore0h.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G", keystore0h.getExtendedPrivateKey(false).toString());

        Keystore keystore0h1h = Keystore.fromMasterPrivateExtendedKey(mpek, KeyDerivation.parsePath("m/0H/1H"));
        Assertions.assertEquals("xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt", keystore0h1h.getExtendedPublicKey().toString());
        Assertions.assertEquals("xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1", keystore0h1h.getExtendedPrivateKey(false).toString());
    }
}
