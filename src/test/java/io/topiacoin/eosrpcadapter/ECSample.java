package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.util.Base58;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.util.Arrays;

public class ECSample {

    public static final String ECC_CURVE_NAME = "secp256k1";

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        String publicKey = "51kdZoTRkCQc7ityw9Jg5LhmFkepq4enjVmQx7cyunQyFUVpz9"; // With the EOS prefix Removed
        String privateKey = "5KTKXhA6QuPFDThASqs1FhQYPaf5P6f9vnAo3bTQvooV93M2oNa";

//        EOSKey key = EOSKey.randomKey();
//        privateKey = key.toWif() ;
//
//        PublicKey eosPubKey = key.getPublicKeyFromPublicString() ;
//        System.out.println ( "Eos Pub Key : " + eosPubKey);

        byte[] publicBytes = Base58.decode(publicKey);
        byte[] privateBytes = Base58.decode(privateKey);

        System.out.println("Private Bytes: " + Hex.encodeHexString(privateBytes));
        System.out.println("Public Bytes : " + Hex.encodeHexString(publicBytes));

        ECPrivateKey privKey = getEcPrivateKey(privateBytes);
        System.out.println("Private Key: " + privKey + " -> " + Hex.encodeHexString(privKey.getEncoded()));

        ECPublicKey extractedPubKey = getPublicKeyFromPrivateKey(privKey);
        System.out.println("Extracted Public Key: " + extractedPubKey+ " -> " + Hex.encodeHexString(extractedPubKey.getEncoded()));

        ECPublicKey pubKey = getEcPublicKey(publicBytes) ;
        System.out.println("Decoded Public Key  : " + pubKey + " -> " + Hex.encodeHexString(pubKey.getEncoded()));
    }

    private static ECPrivateKey getEcPrivateKey(byte[] privateBytes) throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        buffer.put(privateBytes);
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


        BigInteger s = new BigInteger(1, privateKey);

        ECNamedCurveParameterSpec ecCurve = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        ECNamedCurveSpec params = new ECNamedCurveSpec(ECC_CURVE_NAME, ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN(), ecCurve.getH());
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, params);
        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
        return (ECPrivateKey) kf.generatePrivate(keySpec);
    }

    private static ECPublicKey getEcPublicKey(byte[] publicBytes) throws Exception {

        byte[] encodedBytes = new byte[publicBytes.length - 4] ;
        byte[] checksum = new byte[4];
        System.arraycopy(publicBytes, 0, encodedBytes, 0, publicBytes.length - 4);
        System.arraycopy(publicBytes, publicBytes.length - 4, checksum, 0, 4);

        // Verify the checksum
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update((byte)0x80);
        sha256.update(encodedBytes);
        byte[] newChecksum = sha256.digest();
        sha256.reset();
        newChecksum = sha256.digest(newChecksum);
        newChecksum = Arrays.copyOfRange(newChecksum, 0, 4) ;

        // Decode the encoded bytes into an EC Public Key.
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        ECCurve curve = params.getCurve();
        java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, params.getSeed());
        java.security.spec.ECPoint point = ECPointUtil.decodePoint(ellipticCurve, encodedBytes);
        java.security.spec.ECParameterSpec params2 =EC5Util.convertSpec(ellipticCurve, params);
        java.security.spec.ECPublicKeySpec publicKeySpec = new java.security.spec.ECPublicKeySpec(point,params2);

        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");

        return (ECPublicKey)kf.generatePublic(publicKeySpec);
    }

    public static ECPublicKey getPublicKeyFromPrivateKey(ECPrivateKey privateKey) throws  Exception {
        // Generate public key from private key
        // -- Grab the secret S value from the private key, multiply by G to derive Q (aka the public key)
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        ECPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, ECPrivateKeySpec.class);
        ECPoint Q = ecSpec.getG().multiply(privateKeySpec.getS());
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);

        return (ECPublicKey)keyFactory.generatePublic(pubSpec);
    }
}
