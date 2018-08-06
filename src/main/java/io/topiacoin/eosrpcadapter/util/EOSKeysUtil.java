package io.topiacoin.eosrpcadapter.util;

import io.topiacoin.eosrpcadapter.exceptions.KeyException;
import io.topiacoin.eosrpcadapter.exceptions.SignatureException;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
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

    private static final SecureRandom __secureRandom;
    private static final ECNamedCurveParameterSpec __ecCurve;
    private static final ECNamedCurveSpec __ecCurveSpec;

    static {
        __secureRandom = new SecureRandom();
        __ecCurve = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        __ecCurveSpec = new ECNamedCurveSpec(ECC_CURVE_NAME,
                __ecCurve.getCurve(), __ecCurve.getG(), __ecCurve.getN(), __ecCurve.getH());
    }

    /**
     * @return
     *
     * @throws KeyException
     */
    public static ECPrivateKey generateECPrivateKey()
            throws KeyException {
        try {
            byte[] keyBytes = new byte[32];
            __secureRandom.nextBytes(keyBytes);

            // Setup the Key Factory
            KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");

            // Convert keyBytes into BigInteger, then use it to create the Private Key.
            BigInteger s = new BigInteger(1, keyBytes);
            ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, __ecCurveSpec);
            return (ECPrivateKey) kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to create new EC Private Key", e);
        } catch (NoSuchProviderException e) {
            throw new KeyException("Failed to create new EC Private Key", e);
        } catch (InvalidKeySpecException e) {
            throw new KeyException("Failed to create new EC Private Key", e);
        }
    }

    /**
     * @param privateKey
     *
     * @return
     *
     * @throws KeyException
     */
    public static ECPublicKey getPublicKeyFromPrivateKey(
            ECPrivateKey privateKey)
            throws KeyException {
        ECPublicKey publicKey = null;

        try {
            // Setup the key factory.
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");

            // Generate the Key Spec for the private key
            ECPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, ECPrivateKeySpec.class);

            // Calculate the public key EC Point and convert into a Public Key.
            ECPoint Q = __ecCurve.getG().multiply(privateKeySpec.getS());
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, __ecCurve);
            publicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to get Public Key from provided Private Key", e);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    /**
     * @return
     *
     * @throws KeyException
     */
    public static String generateRandomPassword()
            throws KeyException {
        String password = null;

        try {
            SecureRandom secureRandom = new SecureRandom();

            byte[] passwordEntropy = new byte[128];
            secureRandom.nextBytes(passwordEntropy);
            byte[] passwordBytes = sha256x2(passwordEntropy);

            password = "PW" + Base58.encode(passwordBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to create new random password", e);
        }

        return password;
    }

    /**
     * @param signature
     * @param digest
     *
     * @return
     *
     * @throws KeyException
     */
    public static String recoverPublicKey(
            String signature,
            byte[] digest)
            throws KeyException {
        return recoverPublicKey(signature, digest, true);
    }

    /**
     * @param signature
     * @param digest
     *
     * @param legacy
     * @return
     *
     * @throws KeyException
     */
    public static String recoverPublicKey(
            String signature,
            byte[] digest, boolean legacy)
            throws KeyException {
        String publicKeyWif = null;

        try {
            ECCurve ec = __ecCurve.getCurve();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(ec, new byte[0]);
            ECField field = ellipticCurve.getField();

            ECPoint G = __ecCurve.getG();
            BigInteger p = ((java.security.spec.ECFieldFp) field).getP();


            SignatureComponents signatureComponents = checkAndDecodeSignature(signature);

            BigInteger r = signatureComponents.r;
            BigInteger s = signatureComponents.s;

            BigInteger n = __ecCurve.getN();
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
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, __ecCurve);
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);

            publicKeyWif = encodeAndCheckPublicKey(publicKey, legacy);

        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to recover the EC Public Key", e);
        } catch (NoSuchProviderException e) {
            throw new KeyException("Failed to recover the EC Public Key", e);
        } catch (InvalidKeySpecException e) {
            throw new KeyException("Failed to recover the EC Public Key", e);
        }

        return publicKeyWif;
    }

    /**
     * @param publicKeyString
     *
     * @return
     *
     * @throws KeyException
     */
    public static ECPublicKey checkAndDecodePublicKey(
            final String publicKeyString)
            throws KeyException {
        ECPublicKey decodedKey = null;

        try {
            byte[] xBytes = checkAndDecodePublicKeyBytes(publicKeyString);

            // Setup the key factory
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");

            // Calculate the curve point and generate the public key
            ECPoint Q = __ecCurve.getCurve().decodePoint(xBytes);
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, __ecCurve);
            decodedKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to decode Public Key", e);
        } catch (InvalidKeySpecException e) {
            throw new KeyException("Failed to decode Public Key", e);
        } catch (NoSuchProviderException e) {
            throw new KeyException("Failed to decode Public Key", e);
        }

        return decodedKey;
    }

    /**
     * @param publicKeyString
     *
     * @return
     *
     * @throws KeyException
     * @throws IllegalArgumentException
     */
    public static byte[] checkAndDecodePublicKeyBytes(
            String publicKeyString)
            throws KeyException, IllegalArgumentException {
        byte[] xBytes = null;

        try {
            // Verify the public key string is properly formatted
            if (!publicKeyString.startsWith(LEGACY_PUB_KEY_PREFIX) &&
                    !publicKeyString.startsWith(PUB_KEY_PREFIX)) {
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
            byte[] checksum = new byte[4] ;
            byte[] decodedBytes = Base58.decode(trimmedPrivateKeyString);
            xBytes = new byte[decodedBytes.length - 4];
            ByteBuffer buffer = ByteBuffer.wrap(decodedBytes);
            buffer.get(xBytes);
            buffer.get(checksum);

            // Verify the checksum is correct
            byte[] calculatedChecksum;
            if (legacy) {
                // RIPEMD160 Checksum
                calculatedChecksum = ripemd160(xBytes);
            } else {
                // SHA256x2 Checksum
                calculatedChecksum = sha256x2(xBytes);
            }
            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);
            if (!Arrays.equals(checksum, calculatedChecksum)) {
                throw new KeyException("Public Key checksum failed");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to Decode Public Key", e);
        }
        return xBytes;
    }

    /**
     * @param privateKeyWif
     *
     * @return
     *
     * @throws KeyException
     */
    public static ECPublicKey checkAndDecodePublicKeyFromPrivateKeyString(
            String privateKeyWif)
            throws KeyException {
        ECPublicKey publicKey = null;

        ECPrivateKey privateKey = checkAndDecodePrivateKey(privateKeyWif);
        publicKey = getPublicKeyFromPrivateKey(privateKey);

        return publicKey;
    }

    /**
     * @param privateKeyString
     *
     * @return
     *
     * @throws KeyException
     */
    public static ECPrivateKey checkAndDecodePrivateKey(
            final String privateKeyString)
            throws KeyException {
        ECPrivateKey decodedKey = null;

        try {
            byte[] sBytes = checkAndDecodePrivateKeyBytes(privateKeyString);

            // Setup the Key Factory
            KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");

            // Convert key Bytes into a BigInteger, then use it to create the Private Key
            BigInteger s = new BigInteger(1, sBytes);
            ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, __ecCurveSpec);
            decodedKey = (ECPrivateKey) kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to decode Private Key", e);
        } catch (InvalidKeySpecException e) {
            throw new KeyException("Failed to decode Private Key", e);
        } catch (NoSuchProviderException e) {
            throw new KeyException("Failed to decode Private Key", e);
        }

        return decodedKey;
    }

    /**
     * @param privateKeyString
     *
     * @return
     *
     * @throws KeyException
     * @throws IllegalArgumentException
     */
    public static byte[] checkAndDecodePrivateKeyBytes(
            String privateKeyString)
            throws KeyException, IllegalArgumentException {
        byte[] sBytes = null;

        try {
            // Verify the private key string is properly formatted
            if (!privateKeyString.startsWith(LEGACY_PRIV_KEY_PREFIX) &&
                    !privateKeyString.startsWith(PRIV_KEY_PREFIX)) {
                throw new IllegalArgumentException("Unrecognized Private Key format");
            }

            // Check the encoding of the Key (e.g. WIF, PRV_K1)
            // Legacy Prefix is blank, so we have to reverse the logic.
            boolean legacy = !privateKeyString.startsWith(PRIV_KEY_PREFIX);

            // Remove the prefix
            String trimmedPrivateKeyString = privateKeyString;
            if (!legacy) {
                trimmedPrivateKeyString = privateKeyString.replace(PRIV_KEY_PREFIX, "");
            }

            // Decode the string and extract its various components (i.e. S, checksum)
            byte version;
            byte[] checksum = new byte[4];
            byte[] decodedBytes = Base58.decode(trimmedPrivateKeyString);
            sBytes = new byte[decodedBytes.length - 5];
            ByteBuffer buffer = ByteBuffer.wrap(decodedBytes);
            version = buffer.get();
            buffer.get(sBytes);
            buffer.get(checksum);

            // Verify the Version number of the key is correct
            if (version != (byte) 0x80) {
                throw new KeyException("Invalid Private Key String");
            }

            // Verify the checksum is correct (SHA256x2)
            byte[] calculatedChecksum = sha256x2(
                    new byte[]{version},
                    sBytes);
            calculatedChecksum = Arrays.copyOfRange(
                    calculatedChecksum, 0, 4);
            if (!Arrays.equals(checksum, calculatedChecksum)) {
                throw new KeyException("Private Key Checksum failed");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to Decode Private Key", e);
        }

        return sBytes;
    }

    /**
     * @param signatureString
     *
     * @return
     *
     * @throws KeyException
     * @throws IllegalArgumentException
     */
    public static SignatureComponents checkAndDecodeSignature(
            final String signatureString)
            throws KeyException, IllegalArgumentException {
        SignatureComponents components = null;

        try {
            // Verify the private key string is properly formatted
            if (!signatureString.startsWith(LEGACY_SIG_PREFIX)
                    && !signatureString.startsWith(SIG_PREFIX)) {
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
            byte[] calculatedChecksum = ripemd160(
                    new byte[]{i},
                    rBytes,
                    sBytes,
                    "K1".getBytes());
            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);
            if (!Arrays.equals(checksum, calculatedChecksum)) {
                throw new KeyException("Signature Checksum failed");
            }

            // Construct a SignatureComponents object from the components
            components = new SignatureComponents();
            components.r = new BigInteger(1, rBytes);
            components.s = new BigInteger(1, sBytes);
            components.i = i;
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to decode Signature", e);
        }

        return components;
    }

    /**
     * @param publicKey
     *
     * @return
     *
     * @throws KeyException
     */
    public static String encodeAndCheckPublicKey(
            final ECPublicKey publicKey)
            throws KeyException {
        return encodeAndCheckPublicKey(publicKey, true);
    }

    /**
     * @param publicKey
     * @param legacy
     *
     * @return
     *
     * @throws KeyException
     */
    public static String encodeAndCheckPublicKey(
            final ECPublicKey publicKey,
            boolean legacy)
            throws KeyException {
        String encodedKey = null;

        // Extract the ECPoint of the public Key (i.e. X)
        byte[] xBytes = publicKey.getW().getAffineX().toByteArray();
        if (xBytes.length == 33 && xBytes[0] == 0x00) {
            xBytes = Arrays.copyOfRange(xBytes, 1, xBytes.length);
        }
        boolean yIsOdd = publicKey.getW().getAffineY().getLowestSetBit() == 0;
        byte[] publicBytes = new byte[33];
        publicBytes[0] = (byte) (yIsOdd ? 0x03 : 0x02);
        System.arraycopy(
                xBytes, 0,
                publicBytes, 1,
                xBytes.length);

        encodedKey = encodeAndCheckPublicKeyBytes(publicBytes, legacy);

        return encodedKey;
    }

    /**
     * @param publicBytes
     * @param legacy
     *
     * @return
     *
     * @throws KeyException
     */
    public static String encodeAndCheckPublicKeyBytes(
            byte[] publicBytes,
            boolean legacy)
            throws KeyException {
        String encodedKey;

        try {
            // Calculate the checksum based on the format (e.g. RIPEMD160, SHA256x2)
            byte[] calculatedChecksum;
            if (legacy) {
                // RIPEMD160
                calculatedChecksum = ripemd160(publicBytes);
            } else {
                // SHA256x2
                calculatedChecksum = sha256x2(publicBytes);
            }
            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);

            // Assemble the components of the encoded key
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            buffer.put(publicBytes).put(calculatedChecksum).flip();
            byte[] decodedBytes = new byte[buffer.remaining()];
            buffer.get(decodedBytes);

            // Encode the key and append the appropriate prefix.
            encodedKey = (legacy ? LEGACY_PUB_KEY_PREFIX : PUB_KEY_PREFIX);
            encodedKey += Base58.encode(decodedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to encode Public Key", e);
        }

        return encodedKey;
    }

    /**
     * @param privateKey
     *
     * @return
     *
     * @throws KeyException
     */
    public static String encodeAndCheckPrivateKey(
            final ECPrivateKey privateKey)
            throws KeyException {
        return encodeAndCheckPrivateKey(privateKey, true);
    }

    /**
     * @param privateKey
     * @param legacy
     *
     * @return
     *
     * @throws KeyException
     */
    public static String encodeAndCheckPrivateKey(
            final ECPrivateKey privateKey,
            boolean legacy)
            throws KeyException {
        String encodedKey = null;

        // Extract the private ECPoint of the private Key (i.e. S)
        byte[] sBytes = privateKey.getS().toByteArray();
        if (sBytes.length == 33 && sBytes[0] == 0x00) {
            sBytes = Arrays.copyOfRange(sBytes, 1, sBytes.length);
        }
        encodedKey = encodeAndCheckPrivateKeyBytes(sBytes, legacy);

        return encodedKey;
    }

    /**
     * @param sBytes
     * @param legacy
     *
     * @return
     *
     * @throws KeyException
     */
    public static String encodeAndCheckPrivateKeyBytes(
            byte[] sBytes,
            boolean legacy)
            throws KeyException {
        String encodedKey;

        try {
            byte version = (byte) 0x80;

            // Calculate the checksum based on the format (e.g. SHA256x2)
            byte[] calculatedChecksum = sha256x2(
                    new byte[]{version},
                    sBytes);
            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);

            // Assemble the components of the encoded key
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            buffer.put(version).put(sBytes).put(calculatedChecksum).flip();
            byte[] decodedBytes = new byte[buffer.remaining()];
            buffer.get(decodedBytes);

            // Encode the key and append the appropriate prefix.
            encodedKey = (legacy ? LEGACY_PRIV_KEY_PREFIX : PRIV_KEY_PREFIX);
            encodedKey += Base58.encode(decodedBytes);

        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to encode Private Key", e);
        }

        return encodedKey;
    }

    /**
     * @param r
     * @param s
     * @param i
     *
     * @return
     *
     * @throws SignatureException
     */
    public static String encodeAndCheckSignature(
            final BigInteger r,
            final BigInteger s,
            final byte i)
            throws SignatureException {
        return encodeAndCheckSignature(r, s, i, false);
    }

    /**
     * @param r
     * @param s
     * @param i
     * @param legacy
     *
     * @return
     *
     * @throws SignatureException
     */
    public static String encodeAndCheckSignature(
            final BigInteger r,
            final BigInteger s,
            final byte i,
            boolean legacy)
            throws SignatureException {
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

            byte i2 = i ;
            if ( i2 < 4 ) {
                i2 = (byte) (27 + 4 + i);
            }

            // Calculate the checksum based on the format (e.g. RIPEMD160)
            byte[] calculatedChecksum = ripemd160(
                    new byte[]{i2},
                    rBytes,
                    sBytes,
                    "K1".getBytes());
            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);

            // Assemble the components of the encoded key
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            buffer.put(i2).put(rBytes).put(sBytes).put(calculatedChecksum).flip();
            byte[] decodedBytes = new byte[buffer.remaining()];
            buffer.get(decodedBytes);

            isCanonical(decodedBytes);

            // Encode the key and append the appropriate prefix.
            encodedSig = (legacy ? LEGACY_SIG_PREFIX : SIG_PREFIX);
            encodedSig += Base58.encode(decodedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException("Failed to encode Signature", e);
        }

        return encodedSig;
    }

    public static boolean isCanonical(byte[] decodedBytes) {
        boolean canonical = ((decodedBytes[1] & 0x80) == 0);
        canonical &= !(decodedBytes[1] == 0 && ((decodedBytes[2] & 0x80) == 0));
        canonical &= ((decodedBytes[33] & 0x80) == 0);
        canonical &= !(decodedBytes[33] == 0 && ((decodedBytes[34] & 0x80) == 0));

        return canonical;
    }

    public static boolean isCanonical (BigInteger r, BigInteger s) {
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();

        boolean canonical = (rBytes.length == 32) && (sBytes.length == 32) ;
        canonical &= ((rBytes[0] & 0x80) == 0);
        canonical &= !(rBytes[0] == 0 && ((rBytes[1] & 0x80) == 0));
        canonical &= ((sBytes[0] & 0x80) == 0);
        canonical &= !(sBytes[0] == 0 && ((sBytes[1] & 0x80) == 0));

        return canonical;
    }

    /**
     * Calculates the RIPEMD160 hash of the inputs. This algorithm is available in BouncyCastle.  Java has not native
     * support for this algorithm.
     *
     * @param inputs The byte arrays whose hash is being calculated.
     *
     * @return A byte array containing the RIPEMD160 hash of the inputs.
     *
     * @throws NoSuchAlgorithmException If the RIPEMD160 Message Digest is not available.
     */
    private static byte[] ripemd160(byte[]... inputs) throws NoSuchAlgorithmException {
        byte[] hash = null;

        MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160");
        for (byte[] input : inputs) {
            ripemd160.update(input);
        }
        hash = ripemd160.digest();

        return hash;
    }

    /**
     * Calculates the SHA256x2 hash of the inputs.  This algorithm involves calculating the SHA-256 hash of the inputs,
     * then taking the SHA-256 hash of the resulting hash.
     *
     * @param inputs The byte arrays whose hash is being calculated.
     *
     * @return A byte array containing the SHA256x2 hash of the inputs.
     *
     * @throws NoSuchAlgorithmException If Java no longer supports the SHA-256 algorithm.
     */
    private static byte[] sha256x2(byte[]... inputs) throws NoSuchAlgorithmException {
        byte[] hash = null;

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        for (byte[] input : inputs) {
            sha256.update(input);
        }
        hash = sha256.digest();
        hash = sha256.digest(hash);

        return hash;
    }

    /**
     *
     */
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
