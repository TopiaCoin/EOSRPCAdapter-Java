package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.util.Base58;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
//import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
//import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class EOSKey {
    public static final String ECC_CURVE_NAME = "secp256k1";
    private ECPrivateKey privateKey;

    public static EOSKey randomKey() {
        EOSKey newKey = null;
        try {
            SecureRandom sr = new SecureRandom();
            byte[] keyBytes = new byte[32];
            sr.nextBytes(keyBytes);

            ECPrivateKey privateKey = getEcPrivateKey(keyBytes);

            newKey = new EOSKey();
            newKey.privateKey = privateKey;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        return newKey;
    }

    private static ECPrivateKey getEcPrivateKey(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        BigInteger s = new BigInteger(1, keyBytes);

        ECNamedCurveParameterSpec ecCurve = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        ECNamedCurveSpec params = new ECNamedCurveSpec(ECC_CURVE_NAME, ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN(), ecCurve.getH());
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, params);
        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
        return (ECPrivateKey) kf.generatePrivate(keySpec);
    }

    public static EOSKey fromWif(String wif) throws IllegalArgumentException {
        EOSKey eosKey = null;
        try {
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            byte[] rawBytes = Base58.decode(wif);
            buffer.put(rawBytes);
            buffer.flip();

            byte version = buffer.get();
            if (version != (byte) 0x80) {
                throw new IllegalArgumentException("Invalid Private Key.  Wrong Version Number");
            }

            byte[] privateKey = new byte[buffer.remaining() - 4];
            buffer.get(privateKey);

            byte[] checksum = new byte[4];
            buffer.get(checksum);

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(version);
            sha256.update(privateKey);
            byte[] newChecksum = sha256.digest();
            sha256.reset();
            newChecksum = sha256.digest(newChecksum);

            newChecksum = Arrays.copyOfRange(newChecksum, 0, 4) ;

//            System.out.println ( "Checksum    : " + Arrays.toString(checksum)) ;
//            System.out.println ( "New Checksum: " + Arrays.toString(newChecksum)) ;

            if (!Arrays.equals(newChecksum,checksum)) {
                throw new IllegalArgumentException("Invalid WIF Key");
            }

            ECPrivateKey privKey = getEcPrivateKey(privateKey);

            eosKey = new EOSKey();
            eosKey.privateKey = privKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        return eosKey;
    }

    public String toWif() {
        String wif58 = null;
        try {
            byte[] privateBytes = privateKey.getS().toByteArray();

            if ( privateBytes.length == 33 && privateBytes[0] == 0x00 ) {
                privateBytes= Arrays.copyOfRange(privateBytes, 1, privateBytes.length);
            }
//            System.out.println("private Bytes: " + Arrays.toString(Arrays.copyOfRange(privateBytes, 0, 16)));

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            sha256.update((byte) 0x80);
            sha256.update(privateBytes);

            byte[] checksum = sha256.digest();

            sha256.reset();
            sha256.update(checksum);

            checksum = sha256.digest();

//            System.out.println ( "Checksum: " + Arrays.toString(checksum)) ;

            ByteBuffer buffer = ByteBuffer.allocate(1024);
            buffer.put((byte) 0x80);
            buffer.put(privateBytes);
            buffer.put(checksum, 0, 4);
            buffer.flip();

            byte[] wifBytes = new byte[buffer.remaining()];
            buffer.get(wifBytes);

            wif58 = Base58.encode(wifBytes);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return wif58;
    }

    public String getPublicKeyString() {
        String wif58 = null;
        try {
            java.security.spec.ECPoint ecPoint = ((ECPublicKey) getPublicKey()).getW();

            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);

            byte[] encoded = getPublicKey().getEncoded();
//            System.out.println("Encoded Bytes : " + Hex.encodeHexString(encoded));

//            ECPoint ecPoint1 = ecSpec.getCurve().decodePoint(encoded);

            byte[] x = ecPoint.getAffineX().toByteArray();
            byte[] y = ecPoint.getAffineY().toByteArray();
            byte[] publicBytes = new byte[x.length+1];
            int lowestSetBit = ecPoint.getAffineY().getLowestSetBit();
            publicBytes[0] = (byte)(lowestSetBit != 0 ? 0x02 : 0x03); // If bit 0 is not set, number is even.
            System.arraycopy(x, 0, publicBytes, 1, x.length);

//            System.out.println("X Bytes      : " + Hex.encodeHexString(x));
//            System.out.println("Y Bytes      : " + Hex.encodeHexString(y));
//            System.out.println("private Bytes: " + Hex.encodeHexString(publicBytes));

//            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            MessageDigest sha256 = MessageDigest.getInstance("RIPEMD160");

            sha256.update(publicBytes);
//            sha256.update((byte) 0x01);

            byte[] checksum = sha256.digest();

//            sha256.reset();
//            sha256.update(checksum);

//            checksum = sha256.digest();

//            System.out.println ( "Checksum: " + Arrays.toString(checksum)) ;

            ByteBuffer buffer = ByteBuffer.allocate(1024);
//            buffer.put((byte) 0x80);
            buffer.put(publicBytes);
            buffer.put(checksum, 0, 4);
            buffer.flip();

            byte[] wifBytes = new byte[buffer.remaining()];
            buffer.get(wifBytes);

//            wifBytes = getPublicKey().getEncoded();

            wif58 = Base58.encode(wifBytes);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return "EOS" + wif58;
    }

    public PublicKey getPublicKey() {
        PublicKey publicKey = null ;

        try {
            // Generate public key from private key
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);

            ECPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, ECPrivateKeySpec.class);
            ECPoint Q = ecSpec.getG().multiply(privateKeySpec.getS());
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);
            publicKey = keyFactory.generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    protected PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        EOSKey eosKey = (EOSKey) o;

        return privateKey.equals(eosKey.privateKey);
    }

    @Override
    public int hashCode() {
        return privateKey.hashCode();
    }
}
