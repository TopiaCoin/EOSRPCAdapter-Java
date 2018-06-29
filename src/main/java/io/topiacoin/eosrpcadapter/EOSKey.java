package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.util.Base58;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class EOSKey {
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
        }

        return newKey;
    }

    private static ECPrivateKey getEcPrivateKey(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger s = new BigInteger(keyBytes);

        ECNamedCurveParameterSpec ecCurve = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECNamedCurveSpec params = new ECNamedCurveSpec("secp256k1", ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN(), ecCurve.getH());
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, params);
        KeyFactory kf = KeyFactory.getInstance("EC");
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
        }

        return eosKey;
    }

    public String toWif() {
        String wif58 = null;
        try {
            byte[] privateBytes = privateKey.getS().toByteArray();

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
