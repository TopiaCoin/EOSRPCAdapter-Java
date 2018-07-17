package io.topiacoin.eosrpcadapter.util;

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

    public static final String ECC_CURVE_NAME = "secp256k1";

    public static String privateKeyToWif(ECPrivateKey privateKey) throws NoSuchAlgorithmException {
        String privateWif = null;

        // Get the bytes that make up the private key, stripping the extra 0x00 byte if returned.
        byte[] privateBytes = privateKey.getS().toByteArray();

        if ( privateBytes.length == 33 && privateBytes[0] == 0x00 ) {
            privateBytes= Arrays.copyOfRange(privateBytes, 1, privateBytes.length);
        }

        privateWif = keyBytesToPrivateWif(privateBytes);

        return privateWif;
    }

    public static String publicKeyToWif(ECPublicKey publicKey) throws  Exception {
        String publicWif = null;

        // Extract the EC Point from the Public Key.
        java.security.spec.ECPoint ecPoint = publicKey.getW();

        // Grab the coordinate bytes and build the encoded compressed representation.
        byte[] x = ecPoint.getAffineX().toByteArray();
        if ( x.length == 33 && x[0] == 0x00) {
            x = Arrays.copyOfRange(x, 1, x.length);
        }
        byte[] publicBytes = new byte[x.length+1];
        int lowestSetBit = ecPoint.getAffineY().getLowestSetBit();
        publicBytes[0] = (byte)(lowestSetBit != 0 ? 0x02 : 0x03); // If bit 0 is not set, number is even.
        System.arraycopy(x, 0, publicBytes, 1, x.length);

        publicWif = keyBytesToPublicWif(publicBytes);

        return publicWif;
    }

    public static String keyBytesToPrivateWif(byte[] privKey) throws NoSuchAlgorithmException {
        String wif58;

        // Calculate the sha256x2 checksum for the key bytes.
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        sha256.update((byte) 0x80);
        sha256.update(privKey);
        byte[] checksum = sha256.digest();
        sha256.reset();
        sha256.update(checksum);
        checksum = sha256.digest();

        // Build the byte buffer for the WIF key
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        buffer.put((byte) 0x80);
        buffer.put(privKey);
        buffer.put(checksum, 0, 4);
        buffer.flip();

        byte[] wifBytes = new byte[buffer.remaining()];
        buffer.get(wifBytes);

        // Convert the byte buffer into a Base58 string.
        wif58 = Base58.encode(wifBytes);

        return wif58;
    }

    public static String keyBytesToPublicWif(byte[] pubKey) throws NoSuchAlgorithmException {
        String wif58 = null ;

        // Calculate the ripemd160 checksum for this key encoding.
        MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160");
        ripemd160.update(pubKey);
        byte[] checksum = ripemd160.digest();

        // Assemble the byte buffer for the public key.
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        buffer.put(pubKey);
        buffer.put(checksum, 0, 4);
        buffer.flip();
        byte[] wifBytes = new byte[buffer.remaining()];
        buffer.get(wifBytes);

        // Convert the byte buffer into a Base 58 string.
        wif58 = Base58.encode(wifBytes);

        return "EOS" + wif58 ;
    }

    public static byte[] keyBytesFromPrivateWif(String wifString) {
        byte[] keyBytes = Base58.decode(wifString);
        keyBytes = Arrays.copyOfRange(keyBytes, 1, keyBytes.length - 4);
        return keyBytes;
    }

    public static byte[] keyBytesFromPublicWif(String wifString) {
        byte[] keyBytes = Base58.decode(wifString.substring(3));
        keyBytes = Arrays.copyOfRange(keyBytes, 0, keyBytes.length - 4);
        return keyBytes;
    }

    public static ECPrivateKey getPrivateKeyFromPrivateString(String privateKeyWif) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        byte[] rawBytes = Base58.decode(privateKeyWif);
        buffer.put(rawBytes);
        buffer.flip();

        // Read the Version byte out of the key string and verify it is correct
        byte version = buffer.get();
        if (version != (byte) 0x80) {
            throw new IllegalArgumentException("Invalid Private Key.  Wrong Version Number");
        }

        // Fetch out the Key Bytes
        byte[] privateKey = new byte[buffer.remaining() - 4];
        buffer.get(privateKey);

        // Fetch the Key Checksum
        byte[] checksum = new byte[4];
        buffer.get(checksum);

        // Calculate the checksum of the key
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(version);
        sha256.update(privateKey);
        byte[] newChecksum = sha256.digest();
        sha256.reset();
        newChecksum = sha256.digest(newChecksum);

        newChecksum = Arrays.copyOfRange(newChecksum, 0, 4);

        // Verify the calculated checksum matches the provided key checksum.
        if (!Arrays.equals(newChecksum, checksum)) {
            throw new IllegalArgumentException("Invalid WIF Key");
        }

        // Setup the Key Factory and Curve Specs
        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
        ECNamedCurveParameterSpec ecCurve = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        ECNamedCurveSpec params = new ECNamedCurveSpec(ECC_CURVE_NAME, ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN(), ecCurve.getH());

        // Convert the key Bytes into a BigInteger, then create the Private Key from it.
        BigInteger s = new BigInteger(1, privateKey);
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, params);
        return (ECPrivateKey) kf.generatePrivate(keySpec);
    }

    public static ECPublicKey getPublicKeyFromPublicString(String publicKeyWif) throws Exception {
        // Extract encoded point and checksum from the WIF
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        byte[] rawBytes = Base58.decode(publicKeyWif.substring(3));
        byte[] xBytes = Arrays.copyOfRange(rawBytes, 0, rawBytes.length - 4);
        byte[] checksum = Arrays.copyOfRange(rawBytes, rawBytes.length - 4, rawBytes.length) ;

        // Verify the ripemd160 checksum for this key
        MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160");
        ripemd160.update(xBytes);
        byte[] calculatedChecksum = ripemd160.digest();
        calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);
        if ( ! Arrays.equals(checksum, calculatedChecksum)) {
            throw new RuntimeException("Invalid Public Key String") ;
        }

        // Setup the key factory and curve specifications.
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);

        // Calculate the curve point and generate the public key
        ECPoint Q = ecSpec.getCurve().decodePoint(xBytes) ;
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);
        return (ECPublicKey) keyFactory.generatePublic(pubSpec);
    }

    public static ECPublicKey getPublicKeyFromPrivateString(String privateKeyWif) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        ECPublicKey publicKey = null ;

        ECPrivateKey privateKey = getPrivateKeyFromPrivateString(privateKeyWif) ;

        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);

        // Generate the Key Spec for the private key
        ECPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, ECPrivateKeySpec.class);

        // Calculate the public key EC Point and convert into a Public Key.
        ECPoint Q = ecSpec.getG().multiply(privateKeySpec.getS());
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);
        publicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);

        return publicKey ;
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

        password = "PW" + Base58.encode(passwordBytes) ;

        return password;
    }

    public static String recoverPublicKey(String signature, byte[] digest) throws Exception {
        ECNamedCurveParameterSpec ecCurve = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        ECCurve ec = ecCurve.getCurve();
        EllipticCurve ellipticCurve = EC5Util.convertCurve(ec, new byte[0]);
        ECField field = ellipticCurve.getField();

        ECPoint G = ecCurve.getG();
        BigInteger p = ((java.security.spec.ECFieldFp) field).getP();

        String publicKeyWif = null;

        byte[] sigBytes = Base58.decode(signature);
        if ( sigBytes.length != 65 ) {
            throw new RuntimeException("Invalid Signature Length" );
        }
        byte recID = sigBytes[0];
        if ( (recID - 27) != (recID - 27 & 7) ) {
            throw new RuntimeException ("Invalid Signature Parameter");
        }
        recID -= 27 ;
        recID = (byte)(recID & 3);
        byte[] rBytes = Arrays.copyOfRange(sigBytes, 1, 33);
        byte[] sBytes = Arrays.copyOfRange(sigBytes, 33, 33+32);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        BigInteger n = ecCurve.getN();
        BigInteger i = BigInteger.valueOf((long)recID / 2);
        BigInteger x = r.add(i.multiply(n));

        if ( x.compareTo(p) >= 0 ) {
            return "";
        }

        ECPoint R = decompressKey(x, (recID & 1) == 1, ec);

        if ( !R.multiply(n).isInfinity()) {
            throw new RuntimeException("Invalid Signature - Point is not on curve") ;
        }

        BigInteger e = new BigInteger(1, digest) ;

        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint Q = ECAlgorithms.sumOfTwoMultiplies(G, eInvrInv, R, srInv);

        // Create Public Key from Q.
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecCurve);
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);

        publicKeyWif = publicKeyToWif(publicKey);

        return publicKeyWif;
    }

    private static ECPoint decompressKey(BigInteger xBN, boolean yBit,ECCurve curve) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(curve));
        compEnc[0] = (byte)(yBit ? 0x03 : 0x02) ;
        return curve.decodePoint(compEnc);
    }

    public static String recoverPublicKey2(String signature, byte[] digest) throws Exception {

        ECNamedCurveParameterSpec ecCurve = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        ECCurve ec = ecCurve.getCurve();
        EllipticCurve ellipticCurve = EC5Util.convertCurve(ec, new byte[0]);
        ECField field = ellipticCurve.getField();

        BigInteger n = ecCurve.getN();
        ECPoint G = ecCurve.getG();
        BigInteger a = ec.getA().toBigInteger();
        BigInteger b = ec.getB().toBigInteger();
        BigInteger p = ((java.security.spec.ECFieldFp) field).getP();
        BigInteger pOverFour = p.add(BigInteger.ONE).shiftRight(2);

        String publicKeyWif = null;

        byte[] sigBytes = Base58.decode(signature);
        if ( sigBytes.length != 65 ) {
            throw new RuntimeException("Invalid Signature Length" );
        }
        byte i = sigBytes[0];
        if ( (i - 27) != (i - 27 & 7) ) {
            throw new RuntimeException ("Invalid Signature Parameter");
        }
        byte[] rBytes = Arrays.copyOfRange(sigBytes, 1, 33);
        byte[] sBytes = Arrays.copyOfRange(sigBytes, 33, 33+32);

        BigInteger e = new BigInteger(1, digest);
        int messageLength = digest.length * 8;
        if ( n.bitLength() < messageLength) {
            e = e.shiftRight( messageLength - n.bitLength());
            System.out.println("+++ Shifting e");
        }

        byte i2 = i ;
        i2 -= 27;
        i2 = (byte)(i2 & 3);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        if ( ! (r.signum() > 0 && r.compareTo(n) < 0) ) {
            throw new RuntimeException("Invalid r value in Signature");
        }
        if ( ! (s.signum() > 0 && s.compareTo(n) < 0) ) {
            throw new RuntimeException("Invalid s value in Signature");
        }

        boolean isYOdd = ( i2 & 1 ) > 0 ;
        boolean isSecondKey = (i2 >> 1 & 1) > 0;

        // Calculate Y from the given X
        // FIXME - When isSecondKey is true, x is outside the range of the curve!!
        BigInteger x = (isSecondKey ? r.add(n) : r);
        if ( x.compareTo(p) >= 0 ) {
            return "";
        }

        BigInteger alpha = x.pow(3).add(a.multiply(x)).add(b).mod(p);
        BigInteger beta = alpha.modPow(pOverFour, p);

        BigInteger y = beta;
        if ( !beta.testBit(0) ^ !isYOdd ) {
            y = p.subtract(y);
        }

        ECPoint R = ec.createPoint(x, y);

        ECPoint nR = R.multiply(n);
        if ( ! nR.isInfinity() ) {
            throw new RuntimeException("nR is not a valid curve point");
        }

        BigInteger eNeg = e.negate().mod(n);

        BigInteger rInv = r.modInverse(n);

        // (sR + -eG) r^-1
        ECPoint Q = R.multiply(s).add(G.multiply(eNeg)).multiply(rInv);

        // Create Public Key from Q.
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecCurve);
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);

        publicKeyWif = publicKeyToWif(publicKey);

        return publicKeyWif;
    }

    public static String asn1SigToWif(byte[] sigBytes, ECPublicKey publicKey, byte recID) throws Exception {
        ByteBuffer sigbuffer = ByteBuffer.wrap(sigBytes);
        sigbuffer.get();
        sigbuffer.get();
        sigbuffer.get();
        int rLength = sigbuffer.get();
        byte[] r = new byte[rLength] ;
        sigbuffer.get(r);
        sigbuffer.get();
        int sLength = sigbuffer.get();
        byte[] s = new byte[sLength];
        sigbuffer.get(s);

        if (r.length == 33 && r[0] == 0x00) {
            r = Arrays.copyOfRange(r, 1, r.length);
            System.out.println ( "++ Trimmed r") ;
        }
        if ( s.length == 33 && s[0] == 0x00) {
            s = Arrays.copyOfRange(s, 1, s.length);
            System.out.println ( "++ Trimmed s") ;
        }

        byte i = (byte)(27 + 4 + recID) ;

        // Calculate the Checksum of the Signature
        ByteBuffer checksumInput = ByteBuffer.allocate(1024);
        checksumInput.put(i);
        checksumInput.put(r);
        checksumInput.put(s);
        checksumInput.put("K1".getBytes());
        checksumInput.flip();
        byte[] checksumInputBytes = new byte[checksumInput.remaining()];
        checksumInput.get(checksumInputBytes);
        MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160");
        byte[] checksum = ripemd160.digest(checksumInputBytes);

        ByteBuffer wifSigBuffer = ByteBuffer.allocate(1024);
        wifSigBuffer.put(i);
        wifSigBuffer.put(r);
        wifSigBuffer.put(s);
        wifSigBuffer.put(checksum, 0, 4);
        wifSigBuffer.flip();
        sigBytes = new byte[wifSigBuffer.remaining()] ;
        wifSigBuffer.get(sigBytes);

        return Base58.encode(sigBytes);
    }

    public static byte[] wifSigToAsn1(String signature) {
        // Convert EOS Signature back into ASN.1 Signature
        byte[] sigBytes = Base58.decode(signature);
        ByteBuffer sigBuffer = ByteBuffer.wrap(sigBytes);
        byte[] rBytes = new byte[32];
        byte[] sBytes = new byte[32];
        sigBuffer.get() ;
        sigBuffer.get(rBytes);
        sigBuffer.get(sBytes);
        if ( (sBytes[0] >> 7 ) != 0 ) {
            byte[] temp = sBytes ;
            sBytes= new byte[33] ;
            sBytes[0] = 0x00;
            System.arraycopy(temp, 0, sBytes, 1, temp.length);
        }
        if ( (rBytes[0] >> 7 ) != 0 ) {
            byte[] temp = rBytes ;
            rBytes= new byte[33] ;
            rBytes[0] = 0x00;
            System.arraycopy(temp, 0, rBytes, 1, temp.length);
        }
        ByteBuffer asn1Buffer = ByteBuffer.allocate(1024);
        asn1Buffer.put((byte)0x30);
        asn1Buffer.put((byte)(rBytes.length + sBytes.length + 4));
        asn1Buffer.put((byte)0x02);
        asn1Buffer.put((byte)rBytes.length);
        asn1Buffer.put(rBytes);
        asn1Buffer.put((byte)0x02);
        asn1Buffer.put((byte)sBytes.length);
        asn1Buffer.put(sBytes);
        asn1Buffer.flip();
        sigBytes = new byte[asn1Buffer.remaining()];
        asn1Buffer.get(sigBytes);
        return sigBytes;
    }

}
