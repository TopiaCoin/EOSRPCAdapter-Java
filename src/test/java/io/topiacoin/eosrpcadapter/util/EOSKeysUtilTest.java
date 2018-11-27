package io.topiacoin.eosrpcadapter.util;

import io.topiacoin.eosrpcadapter.exceptions.KeyException;
import io.topiacoin.eosrpcadapter.exceptions.SignatureException;
import io.topiacoin.eosrpcadapter.exceptions.WalletException;
import org.apache.http.util.TextUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static junit.framework.TestCase.*;

public class EOSKeysUtilTest {

    @BeforeClass
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGenerateRandomPassword() throws Exception {
        String password = EOSKeysUtil.generateRandomPassword();

        assertNotNull("No Password Returned", password);
        assertFalse("No Password Returned", TextUtils.isEmpty(password));
    }

    @Test
    public void testCreateKey() throws Exception {
        ECPrivateKey privateKey = EOSKeysUtil.generateECPrivateKey();

        assertNotNull("No Private Key Returned", privateKey);
    }

    @Test
    public void testEncodeDecodePrivateKey() throws Exception {

        ECPrivateKey privateKey = EOSKeysUtil.generateECPrivateKey();

        String legacyPrivKeyStr = EOSKeysUtil.encodeAndCheckPrivateKey(privateKey, true);
        assertNotNull("Unable to Encode Private Key", legacyPrivKeyStr);
        assertFalse("Unable to Encode Private Key", TextUtils.isEmpty(legacyPrivKeyStr));

        String currentPrivKeyStr = EOSKeysUtil.encodeAndCheckPrivateKey(privateKey, false);
        assertNotNull("Unable to Encode Private Key", currentPrivKeyStr);
        assertFalse("Unable to Encode Private Key", TextUtils.isEmpty(currentPrivKeyStr));

        ECPrivateKey legacyPrivateKey = EOSKeysUtil.checkAndDecodePrivateKey(legacyPrivKeyStr);
        assertNotNull("Unable to Decode Private Key", legacyPrivateKey);
        assertEquals("Unable to Decode Private Key", privateKey, legacyPrivateKey);

        ECPrivateKey currentPrivateKey = EOSKeysUtil.checkAndDecodePrivateKey(currentPrivKeyStr);
        assertNotNull("Unable to Decode Private Key", currentPrivateKey);
        assertEquals("Unable to Decode Private Key", privateKey, currentPrivateKey);
    }

    @Test
    public void testEncodeDecodePublicKey() throws Exception {

        ECPrivateKey privateKey = EOSKeysUtil.generateECPrivateKey();
        ECPublicKey publicKey = EOSKeysUtil.getPublicKeyFromPrivateKey(privateKey);

        String legacyPubKeyStr = EOSKeysUtil.encodeAndCheckPublicKey(publicKey, true);
        assertNotNull("Unable to Encode Public Key", legacyPubKeyStr);
        assertFalse("Unable to Encode Public Key", TextUtils.isEmpty(legacyPubKeyStr));

        String currentPubKeyStr = EOSKeysUtil.encodeAndCheckPublicKey(publicKey, false);
        assertNotNull("Unable to Encode Public Key", currentPubKeyStr);
        assertFalse("Unable to Encode Public Key", TextUtils.isEmpty(currentPubKeyStr));

        ECPublicKey legacyPublicKey = EOSKeysUtil.checkAndDecodePublicKey(legacyPubKeyStr);
        assertNotNull("Unable to Decode Public Key", legacyPublicKey);
        assertEquals("Unable to Decode Public Key", publicKey, legacyPublicKey);

        ECPublicKey currentPublicKey = EOSKeysUtil.checkAndDecodePublicKey(currentPubKeyStr);
        assertNotNull("Unable to Decode Public Key", currentPublicKey);
        assertEquals("Unable to Decode Public Key", publicKey, currentPublicKey);
    }

    @Test
    public void testEncodeDecodeSignature() throws Exception {

        String data = "I am the very model of a modern major general";
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes());

        ECPrivateKey privateKey = EOSKeysUtil.generateECPrivateKey();

        String legacySignature = signDigest(digest, privateKey, true);
        String currentSignature = signDigest(digest, privateKey, false);

        EOSKeysUtil.SignatureComponents legacySigComp = EOSKeysUtil.checkAndDecodeSignature(legacySignature);
        assertNotNull("A Legacy Signature Components were not returned", legacySigComp);

        String legacyRecoveredSig = EOSKeysUtil.encodeAndCheckSignature(
                legacySigComp.r, legacySigComp.s, legacySigComp.i, true);
        assertNotNull ("A Legacy Recovered Signature was not returned", legacyRecoveredSig) ;
        assertEquals("The Recovered Legacy Signature does not match", legacySignature, legacyRecoveredSig);

        EOSKeysUtil.SignatureComponents currentSigComp = EOSKeysUtil.checkAndDecodeSignature(currentSignature);
        assertNotNull("A Current  Signature Components were not returned",currentSigComp);

        String currentRecoveredSig = EOSKeysUtil.encodeAndCheckSignature(
                currentSigComp.r, currentSigComp.s, currentSigComp.i, false);
        assertNotNull ("A Current Recovered Signature was not returned", currentRecoveredSig) ;
        assertEquals("The Current Legacy Signature does not match", currentSignature, currentRecoveredSig);
    }

    @Test
    public void testRecoverPublicKey() throws Exception {

        String data = "I am the very model of a modern major general";
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes());

        ECPrivateKey privateKey = EOSKeysUtil.generateECPrivateKey();
        ECPublicKey publicKey = EOSKeysUtil.getPublicKeyFromPrivateKey(privateKey);

        String legacySignature = signDigest(digest, privateKey, true);
        String currentSignature = signDigest(digest, privateKey, false);

        String recoveredLegacyPubKey = EOSKeysUtil.recoverPublicKey(legacySignature, digest, true);
        assertNotNull("Unable to Recover Public Key", recoveredLegacyPubKey);
        assertEquals("Wrong Public Key Recovered",
                publicKey, EOSKeysUtil.checkAndDecodePublicKey(recoveredLegacyPubKey));

        String recoveredCurrentPubKey = EOSKeysUtil.recoverPublicKey(legacySignature, digest, false);
        assertNotNull("Unable to Recover Public Key", recoveredCurrentPubKey);
        assertEquals("Wrong Public Key Recovered",
                publicKey, EOSKeysUtil.checkAndDecodePublicKey(recoveredCurrentPubKey));

        recoveredLegacyPubKey = EOSKeysUtil.recoverPublicKey(currentSignature, digest, true);
        assertNotNull("Unable to Recover Public Key", recoveredLegacyPubKey);
        assertEquals("Wrong Public Key Recovered",
                publicKey, EOSKeysUtil.checkAndDecodePublicKey(recoveredLegacyPubKey));

        recoveredCurrentPubKey = EOSKeysUtil.recoverPublicKey(currentSignature, digest, false);
        assertNotNull("Unable to Recover Public Key", recoveredCurrentPubKey);
        assertEquals("Wrong Public Key Recovered",
                publicKey, EOSKeysUtil.checkAndDecodePublicKey(recoveredCurrentPubKey));
    }


    /*
     *  This signing method was copied from the JavaWallet.EOSWallet class for use in this test.
     */
    private String signDigest(byte[] digest, ECPrivateKey privateKey, boolean legacy) throws WalletException, KeyException, SignatureException {
        String signature = null;

        String publicKeyWif = EOSKeysUtil.encodeAndCheckPublicKey(EOSKeysUtil.getPublicKeyFromPrivateKey(privateKey));

        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(EOSKeysUtil.ECC_CURVE_NAME);
        ECDomainParameters curve = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),
                params.getH());

        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKey.getS(), curve);
        signer.init(true, privKey);

        BigInteger[] components;
        components = signer.generateSignature(digest);

        BigInteger r = components[0];
        BigInteger s = components[1];

        int i = 0;
        while (i < 4) {
            String testSig = EOSKeysUtil.encodeAndCheckSignature(r, s, (byte) i++, legacy);
            String recoveredKey = EOSKeysUtil.recoverPublicKey(testSig, digest);
            if (publicKeyWif.equals(recoveredKey)) {
                signature = testSig;
                break;
            }
        }

        return signature;
    }

    @Test
    public void testStuff() throws Exception {
        String key = "EOS55MHXAq4AJ6Gzm9fAxKbUQL9pcLHaZYc9toYdWhg9DPswizRSc" ;
        String hexKey = "000218a936f03e2adc1603c84f063baf5591650aad6de8cf702b924474a91f843905";

        byte[] keyBytes = EOSKeysUtil.checkAndDecodePublicKeyBytes(key) ;

        String keyBytesHex = "00" + Hex.toHexString(keyBytes) ;

        assertEquals ( hexKey, keyBytesHex) ;
    }
}
