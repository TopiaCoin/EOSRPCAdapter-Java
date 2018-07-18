package io.topiacoin.eosrpcadapter.util;

import io.topiacoin.eosrpcadapter.exceptions.WalletException;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class EOSKeysUtil {

    public static final String PUB_KEY_PREFIX = "PUB_K1_";
    public static final String PRIV_KEY_PREFIX = "PRV_K1_";
    public static final String SIG_PREFIX = "SIG_K1_";

    public static final String LEGACY_PUB_KEY_PREFIX = "EOS";
    public static final String LEGACY_PRIV_KEY_PREFIX = "";
    public static final String LEGACY_SIG_PREFIX = "EOS";

    public static final String ECC_CURVE_NAME = "secp256k1";

    public static ECPrivateKey getPrivateKeyFromPrivateString(String privateKeyWif) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        ECPrivateKey privateKey = null;
        try {
            privateKey = checkAndDecodePrivateKey(privateKeyWif);
        } catch (WalletException e) {
            e.printStackTrace();
            // TODO - Handle this Exception
        }
        return privateKey;
    }

    public static ECPublicKey getPublicKeyFromPublicString(String publicKeyWif) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        ECPublicKey publicKey = null;
        try {
            publicKey = checkAndDecodePublicKey(publicKeyWif);
        } catch (WalletException e) {
            e.printStackTrace();
            // TODO - Handle this Exception
        }
        return publicKey;
    }

    public static ECPublicKey getPublicKeyFromPrivateString(String privateKeyWif) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        ECPublicKey publicKey = null;

        try {
            ECPrivateKey privateKey = checkAndDecodePrivateKey(privateKeyWif);
            publicKey = getPublicKeyFromPrivateKey(privateKey);
        } catch (WalletException e) {
            e.printStackTrace();
            // TODO - Handle this Exception
        } catch (Exception e) {
            e.printStackTrace();
            // TODO - Handle this Exception
        }

        return publicKey;
    }

    public static ECPrivateKey generateECPrivateKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        SecureRandom sr = new SecureRandom();
        byte[] keyBytes = new byte[32];
        sr.nextBytes(keyBytes);

        // Setup the Key Factory and Curve Specs
        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
        ECNamedCurveParameterSpec ecCurve = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        ECNamedCurveSpec params = new ECNamedCurveSpec(ECC_CURVE_NAME, ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN(), ecCurve.getH());

        // Convert the key Bytes into a BigInteger, then create the Private Key from it.
        BigInteger s = new BigInteger(1, keyBytes);
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, params);
        return (ECPrivateKey) kf.generatePrivate(keySpec);
    }

    public static ECPublicKey getPublicKeyFromPrivateKey(ECPrivateKey privateKey) throws Exception {
        ECPublicKey publicKey = null;

        // Setup the key factory and curve specifications.
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);

        // Generate the Key Spec for the private key
        ECPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, ECPrivateKeySpec.class);

        // Calculate the public key EC Point and convert into a Public Key.
        ECPoint Q = ecSpec.getG().multiply(privateKeySpec.getS());
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);
        publicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);

        return publicKey;
    }

    public static String generateRandomPassword() throws NoSuchAlgorithmException {
        String password = null;

        SecureRandom secureRandom = new SecureRandom();

        byte[] passwordEntropy = new byte[128];
        secureRandom.nextBytes(passwordEntropy);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] passwordBytes = sha256.digest(passwordEntropy);

        password = "PW" + Base58.encode(passwordBytes);

        return password;
    }

    public static String recoverPublicKey(String signature, byte[] digest) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec ecCurve = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        ECCurve ec = ecCurve.getCurve();
        EllipticCurve ellipticCurve = EC5Util.convertCurve(ec, new byte[0]);
        ECField field = ellipticCurve.getField();

        ECPoint G = ecCurve.getG();
        BigInteger p = ((java.security.spec.ECFieldFp) field).getP();

        String publicKeyWif = null;

        SignatureComponents signatureComponents = null;
        try {
            signatureComponents = checkAndDecodeSignature(signature);
        } catch (WalletException e) {
            e.printStackTrace();
            // TODO - Handle this Exception
        }

        BigInteger r = signatureComponents.r;
        BigInteger s = signatureComponents.s;

        BigInteger n = ecCurve.getN();
        byte i2 = signatureComponents.i;
        i2 -= 27;
        i2 = (byte) (i2 & 3);
        BigInteger i = BigInteger.valueOf((long) i2 / 2);
        BigInteger x = r.add(i.multiply(n));

        if (x.compareTo(p) >= 0) {
            return "";
        }

        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(x, 1 + x9.getByteLength(ec));
        compEnc[0] = (byte) ((signatureComponents.i & 1) == 1 ? 0x03 : 0x02);
        ECPoint R = ec.decodePoint(compEnc);

        if (!R.multiply(n).isInfinity()) {
            throw new RuntimeException("Invalid Signature - Point is not on curve");
        }

        BigInteger e = new BigInteger(1, digest);

        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint Q = ECAlgorithms.sumOfTwoMultiplies(G, eInvrInv, R, srInv);

        // Create Public Key from Q.
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecCurve);
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);

        try {
            publicKeyWif = encodeAndCheckPublicKey(publicKey);
        } catch (WalletException e1) {
            e1.printStackTrace();
            // TODO - Handle this Exception
        }

        return publicKeyWif;
    }

    public static ECPublicKey checkAndDecodePublicKey(final String publicKeyString) throws WalletException {
        ECPublicKey decodedKey = null;

        try {
            byte[] xBytes = checkAndDecodePublicKeyBytes(publicKeyString);

            // Construct a ECPublicKey object from the components
            // Setup the key factory and curve specifications.
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);

            // Calculate the curve point and generate the public key
            ECPoint Q = ecSpec.getCurve().decodePoint(xBytes);
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);
            decodedKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Failed to decode Public Key", e);
        } catch (InvalidKeySpecException e) {
            throw new WalletException("Failed to decode Public Key", e);
        } catch (NoSuchProviderException e) {
            throw new WalletException("Failed to decode Public Key", e);
        }

        return decodedKey;
    }

    public static byte[] checkAndDecodePublicKeyBytes(String publicKeyString) throws WalletException {
        byte[] xBytes = null;

        try {
            // Verify the public key string is properly formatted
            if (!publicKeyString.startsWith(LEGACY_PUB_KEY_PREFIX) && !publicKeyString.startsWith(PUB_KEY_PREFIX)) {
                throw new IllegalArgumentException("Unrecognized Public Key format");
            }

            // Check the encoding of the Key (e.g. EOS/WIF, PUB_K1)
            boolean legacy = publicKeyString.startsWith(LEGACY_PUB_KEY_PREFIX);

            // Remove the prefix
            String trimmedPrivateKeyString;
            if (legacy) {
                trimmedPrivateKeyString = publicKeyString.replace(LEGACY_PUB_KEY_PREFIX, "");
            } else {
                trimmedPrivateKeyString = publicKeyString.replace(PUB_KEY_PREFIX, "");
            }

            // Decode the string and extract its various components (i.e. X, checksum)
            byte[] decodedBytes = Base58.decode(trimmedPrivateKeyString);
            byte[] checksum = Arrays.copyOfRange(decodedBytes, decodedBytes.length - 4, decodedBytes.length);
            xBytes = Arrays.copyOfRange(decodedBytes, 0, decodedBytes.length - 4);

            // Verify the checksum is correct
            byte[] calculatedChecksum;
            if (legacy) {
                // RIPEMD160 Checksum
                MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160");
                calculatedChecksum = ripemd160.digest(xBytes);
            } else {
                // SHA256x2 Checksum
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                calculatedChecksum = sha256.digest(xBytes);
                calculatedChecksum = sha256.digest(calculatedChecksum);
            }
            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);
            if (!Arrays.equals(checksum, calculatedChecksum)) {
                throw new WalletException("Public Key checksum failed");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Failed to Decode Public Key", e);
        }
        return xBytes;
    }

    public static ECPrivateKey checkAndDecodePrivateKey(final String privateKeyString) throws WalletException {
        ECPrivateKey decodedKey = null;

        try {
            byte[] sBytes = checkAndDecodePrivateKeyBytes(privateKeyString);

            // Construct a ECPrivateKey object from the components
            // Setup the Key Factory and Curve Specs
            KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
            ECNamedCurveParameterSpec ecCurve = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
            ECNamedCurveSpec params = new ECNamedCurveSpec(ECC_CURVE_NAME, ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN(), ecCurve.getH());

            // Convert the key Bytes into a BigInteger, then create the Private Key from it.
            BigInteger s = new BigInteger(1, sBytes);
            ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, params);
            decodedKey = (ECPrivateKey) kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Failed to decode Private Key", e);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        return decodedKey;
    }

    public static byte[] checkAndDecodePrivateKeyBytes(String privateKeyString) throws WalletException {
        byte[] sBytes = null;

        try {
            // Verify the private key string is properly formatted
            if (!privateKeyString.startsWith(LEGACY_PRIV_KEY_PREFIX) && !privateKeyString.startsWith(PRIV_KEY_PREFIX)) {
                throw new IllegalArgumentException("Unrecognized Private Key format");
            }

            // Check the encoding of the Key (e.g. WIF, PRV_K1)
            boolean legacy = !privateKeyString.startsWith(PRIV_KEY_PREFIX); // Legacy Prefix is blank, so we have to reverse the logic.

            // Remove the prefix
            String trimmedPrivateKeyString = privateKeyString;
            if (!legacy) {
                trimmedPrivateKeyString = privateKeyString.replace(PRIV_KEY_PREFIX, "");
            }

            // Decode the string and extract its various components (i.e. S, checksum)
            byte[] decodedBytes = Base58.decode(trimmedPrivateKeyString);
            if (decodedBytes[0] != (byte) 0x80) {
                throw new WalletException("Invalid Private Key String");
            }
            byte[] checksum = Arrays.copyOfRange(decodedBytes, decodedBytes.length - 4, decodedBytes.length);
            sBytes = Arrays.copyOfRange(decodedBytes, 1, decodedBytes.length - 4);

            // Verify the checksum is correct (SHA256x2)
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(decodedBytes[0]); // Version Identifier
            sha256.update(sBytes);
            byte[] calculatedChecksum = sha256.digest();
            calculatedChecksum = sha256.digest(calculatedChecksum);

            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);
            if (!Arrays.equals(checksum, calculatedChecksum)) {
                throw new WalletException("Private Key Checksum failed");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Failed to Decode Private Key", e);
        }

        return sBytes;
    }

    public static SignatureComponents checkAndDecodeSignature(final String signatureString) throws WalletException {
        SignatureComponents components = null;

        try {
            // Verify the private key string is properly formatted
            if (!signatureString.startsWith(LEGACY_SIG_PREFIX) && !signatureString.startsWith(SIG_PREFIX)) {
                throw new IllegalArgumentException("Unrecognized Signature format");
            }

            // Check the encoding of the Signature (e.g. EOS/WIF, SIG_K1)
            boolean legacy = signatureString.startsWith(LEGACY_SIG_PREFIX);

            // Remove the prefix
            String trimmedPrivateKeyString;
            if (legacy) {
                trimmedPrivateKeyString = signatureString.replace(LEGACY_SIG_PREFIX, "");
            } else {
                trimmedPrivateKeyString = signatureString.replace(SIG_PREFIX, "");
            }

            // Decode the string and extract its various components (i.e. R, S, i)
            byte[] decodedBytes = Base58.decode(trimmedPrivateKeyString);
            byte i = decodedBytes[0];
            byte[] rBytes = Arrays.copyOfRange(decodedBytes, 1, 33);
            byte[] sBytes = Arrays.copyOfRange(decodedBytes, 33, 65);
            byte[] checksum = Arrays.copyOfRange(decodedBytes, 65, 69);

            // Verify the checksum is correct
            byte[] calculatedChecksum;
            MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160");
            ripemd160.update(i);
            ripemd160.update(rBytes);
            ripemd160.update(sBytes);
            ripemd160.update("K1".getBytes());
            calculatedChecksum = ripemd160.digest();
            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);
            if (!Arrays.equals(checksum, calculatedChecksum)) {
                throw new WalletException("Signature Checksum failed");
            }

            // Construct a SignatureComponents object from the components
            components = new SignatureComponents();
            components.r = new BigInteger(1, rBytes);
            components.s = new BigInteger(1, sBytes);
            components.i = i;
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Failed to decode Signature", e);
        }

        return components;
    }

    public static String encodeAndCheckPublicKey(final ECPublicKey publicKey) throws WalletException {
        return encodeAndCheckPublicKey(publicKey, true);
    }

    public static String encodeAndCheckPublicKey(final ECPublicKey publicKey, boolean legacy) throws WalletException {
        String encodedKey = null;

        // Extract the ECPoint of the public Key (i.e. X)
        byte[] xBytes = publicKey.getW().getAffineX().toByteArray();
        if (xBytes.length == 33 && xBytes[0] == 0x00) {
            xBytes = Arrays.copyOfRange(xBytes, 1, xBytes.length);
        }
        boolean yIsOdd = publicKey.getW().getAffineY().getLowestSetBit() == 0;
        byte[] publicBytes = new byte[33];
        publicBytes[0] = (byte) (yIsOdd ? 0x03 : 0x02);
        System.arraycopy(xBytes, 0, publicBytes, 1, xBytes.length);

        encodedKey = encodeAndCheckPublicKeyBytes(publicBytes, legacy);

        return encodedKey;
    }

    public static String encodeAndCheckPublicKeyBytes(byte[] publicBytes, boolean legacy) throws WalletException {
        String encodedKey;// Calculate the checksum based on the format (e.g. RIPEMD160, SHA256x2)

        try {
            byte[] calculatedChecksum;
            if (legacy) {
                // RIPEMD160
                MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160");
                calculatedChecksum = ripemd160.digest(publicBytes);
            } else {
                // SHA256x2
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                calculatedChecksum = sha256.digest(publicBytes);
                calculatedChecksum = sha256.digest(calculatedChecksum);
            }
            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);

            // Assemble the components of the encoded key
            byte[] decodedBytes = new byte[publicBytes.length + calculatedChecksum.length];
            System.arraycopy(publicBytes, 0, decodedBytes, 0, publicBytes.length);
            System.arraycopy(calculatedChecksum, 0, decodedBytes, publicBytes.length, calculatedChecksum.length);

            // Encode the key and append the appropriate prefix.
            encodedKey = (legacy ? LEGACY_PUB_KEY_PREFIX : PUB_KEY_PREFIX);
            encodedKey += Base58.encode(decodedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Failed to encode Public Key", e);
        }

        return encodedKey;
    }

    public static String encodeAndCheckPrivateKey(final ECPrivateKey privateKey) throws WalletException {
        return encodeAndCheckPrivateKey(privateKey, true);
    }

    public static String encodeAndCheckPrivateKey(final ECPrivateKey privateKey, boolean legacy) throws WalletException {
        String encodedKey = null;

        // Extract the private ECPoint of the private Key (i.e. S)
        byte[] sBytes = privateKey.getS().toByteArray();
        if (sBytes.length == 33 && sBytes[0] == 0x00) {
            sBytes = Arrays.copyOfRange(sBytes, 1, sBytes.length);
        }
        encodedKey = encodeAndCheckPrivateKeyBytes(sBytes, legacy);

        return encodedKey;
    }

    public static String encodeAndCheckPrivateKeyBytes(byte[] sBytes, boolean legacy) throws WalletException {
        String encodedKey;

        try {
            byte version = (byte) 0x80;

            // Calculate the checksum based on the format (e.g. SHA256x2)
            byte[] calculatedChecksum;
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(version);
            sha256.update(sBytes);
            calculatedChecksum = sha256.digest();
            calculatedChecksum = sha256.digest(calculatedChecksum);
            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);

            // Assemble the components of the encoded key
            byte[] decodedBytes = new byte[sBytes.length + calculatedChecksum.length + 1];
            decodedBytes[0] = (byte) 0x80;
            System.arraycopy(sBytes, 0, decodedBytes, 1, sBytes.length);
            System.arraycopy(calculatedChecksum, 0, decodedBytes, sBytes.length + 1, calculatedChecksum.length);

            // Encode the key and append the appropriate prefix.
            encodedKey = (legacy ? LEGACY_PRIV_KEY_PREFIX : PRIV_KEY_PREFIX);
            encodedKey += Base58.encode(decodedBytes);

        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Failed to encode Private Key", e);
        }

        return encodedKey;
    }

    public static String encodeAndCheckSignature(final BigInteger r, final BigInteger s, final byte i) throws WalletException {
        return encodeAndCheckSignature(r, s, i, false);
    }

    public static String encodeAndCheckSignature(final BigInteger r, final BigInteger s, final byte i, boolean legacy) throws WalletException {
        String encodedSig = null;

        try {
            byte[] rBytes = r.toByteArray();
            if (rBytes.length == 33 && rBytes[0] == 0x00) {
                rBytes = Arrays.copyOfRange(rBytes, 1, 33);
            }
            byte[] sBytes = s.toByteArray();
            if (sBytes.length == 33 && sBytes[0] == 0x00) {
                sBytes = Arrays.copyOfRange(sBytes, 1, 33);
            }

            byte i2 = (byte) (27 + 4 + i);

            // Calculate the checksum based on the format (e.g. RIPEMD160)
            byte[] calculatedChecksum;
            MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160");
            ripemd160.update(i2);
            ripemd160.update(rBytes);
            ripemd160.update(sBytes);
            ripemd160.update("K1".getBytes());
            calculatedChecksum = ripemd160.digest();
            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);

            // Assemble the components of the encoded key
            byte[] decodedBytes = new byte[rBytes.length + sBytes.length + calculatedChecksum.length + 1];
            decodedBytes[0] = i2;
            System.arraycopy(rBytes, 0, decodedBytes, 1, rBytes.length);
            System.arraycopy(sBytes, 0, decodedBytes, rBytes.length + 1, sBytes.length);
            System.arraycopy(calculatedChecksum, 0, decodedBytes, rBytes.length + sBytes.length + 1, calculatedChecksum.length);

            // Encode the key and append the appropriate prefix.
            encodedSig = (legacy ? LEGACY_SIG_PREFIX : SIG_PREFIX);
            encodedSig += Base58.encode(decodedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Failed to encode Signature", e);
        }

        return encodedSig;
    }

    public static class SignatureComponents {
        public BigInteger r;
        public BigInteger s;
        public byte i;

        @Override
        public String toString() {
            return "SignatureComponents{\n" +
                    "    r=" + r + "\n" +
                    "    s=" + s + "\n" +
                    "    i=" + i +
                    '}';
        }
    }
}
