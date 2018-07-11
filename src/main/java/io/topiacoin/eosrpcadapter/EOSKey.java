package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.util.Base58;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class EOSKey {
    public static final String ECC_CURVE_NAME = "secp256k1";
    private ECPrivateKey privateKey;

    /**
     * Returns a randomly generated EOSKey.  The key is created using 32 bytes of random data that is
     * converted into an EC Private Key.  The returned object contains this private key and can be used
     * for signing, verifying, and retrieving the matching public key.
     *
     * @return A new EOSKey object containing a randomly generated EC Private Key.
     */
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

    /**
     * Constructs an EOSKey object from a WIF encoded private key string.
     *
     * @param wif The WIF encoded private key string.
     *
     * @return A newly consturcted EOSKey object containing the private key represented by the specified string.
     *
     * @throws IllegalArgumentException If the private key string does not represent a properly encoded private key.
     */
    public static EOSKey fromWif(String wif) throws IllegalArgumentException {
        EOSKey eosKey = null;
        try {
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            byte[] rawBytes = Base58.decode(wif);
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

            newChecksum = Arrays.copyOfRange(newChecksum, 0, 4) ;

            // Verify the calculated checksum matches the provided key checksum.
            if (!Arrays.equals(newChecksum,checksum)) {
                throw new IllegalArgumentException("Invalid WIF Key");
            }

            // Obtain the EC Private Key from the Key bytes
            ECPrivateKey privKey = getEcPrivateKey(privateKey);

            eosKey = new EOSKey();
            eosKey.privateKey = privKey;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to load the required Encryption Algorithm",e );
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid Private Key.");
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Failed to load the required Encryption Provider",e );
        }

        return eosKey;
    }

    /**
     * Returns a WIF encoded version of the Private Key.
     *
     * @return A string containing the WIF encoded version of the private key.
     */
    public String toWif() {
        String wif58 = null;
        try {
            // Get the bytes that make up the private key, stripping the extra 0x00 byte if returned.
            byte[] privateBytes = privateKey.getS().toByteArray();

            if ( privateBytes.length == 33 && privateBytes[0] == 0x00 ) {
                privateBytes= Arrays.copyOfRange(privateBytes, 1, privateBytes.length);
            }

            // Calculate the sha256x2 checksum for the key bytes.
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            sha256.update((byte) 0x80);
            sha256.update(privateBytes);
            byte[] checksum = sha256.digest();
            sha256.reset();
            sha256.update(checksum);
            checksum = sha256.digest();

            // Build the byte buffer for the WIF key
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            buffer.put((byte) 0x80);
            buffer.put(privateBytes);
            buffer.put(checksum, 0, 4);
            buffer.flip();

            byte[] wifBytes = new byte[buffer.remaining()];
            buffer.get(wifBytes);

            // Convert the byte buffer into a Base58 string.
            wif58 = Base58.encode(wifBytes);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to load the required Encryption Algorithm",e );
        }

        return wif58;
    }

    /**
     * Returns a WIF encoded version of the Public Key associated with the private key contained in this object.
     * The returned string will include the "EOS" prefix.
     *
     * @return A string containing the WIF encoded Public Key.
     */
    public String getPublicKeyString() {
        String wif58 = null;
        try {
            // Extract the EC Point from the Public Key.
            java.security.spec.ECPoint ecPoint = ((ECPublicKey) getPublicKey()).getW();

            // Grab the coordinate bytes and build the encoded compressed representation.
            byte[] x = ecPoint.getAffineX().toByteArray();
            byte[] publicBytes = new byte[x.length+1];
            int lowestSetBit = ecPoint.getAffineY().getLowestSetBit();
            publicBytes[0] = (byte)(lowestSetBit != 0 ? 0x02 : 0x03); // If bit 0 is not set, number is even.
            System.arraycopy(x, 0, publicBytes, 1, x.length);

            // Calculate the ripemd160 checksum for this key encoding.
            MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160");
            ripemd160.update(publicBytes);
            byte[] checksum = ripemd160.digest();

            // Assemble the byte buffer for the public key.
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            buffer.put(publicBytes);
            buffer.put(checksum, 0, 4);
            buffer.flip();
            byte[] wifBytes = new byte[buffer.remaining()];
            buffer.get(wifBytes);

            // Convert the byte buffer into a Base 58 string.
            wif58 = Base58.encode(wifBytes);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to load the required Encryption Algorithm",e );
        }

        return "EOS" + wif58;
    }

    /**
     * Returns the Public Key that corresponds to the PrivateKey contained within this EOSKey instance.
     *
     * @return The PublicKey that corresponds to this instances PrivateKey.
     */
    public PublicKey getPublicKey() {
        PublicKey publicKey = null ;

        // Generate public key from private key
        try {
            // Setup the key factory and curve specifications.
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);

            // Generate the Key Spec for the private key
            ECPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, ECPrivateKeySpec.class);

            // Calculate the public key EC Point and convert into a Public Key.
            ECPoint Q = ecSpec.getG().multiply(privateKeySpec.getS());
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);
            publicKey = keyFactory.generatePublic(pubSpec);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to load the required Encryption Algorithm",e );
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Failed to load the required Encryption Provider",e );
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid Private Key.");
        }

        return publicKey;
    }

    /**
     * Returns the Private Key object contained within this EOSKey instance.
     *
     * @return The PrivateKey contained within this EOSKey instance.
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    private static ECPrivateKey getEcPrivateKey(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        // Setup the Key Factory and Curve Specs
        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
        ECNamedCurveParameterSpec ecCurve = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        ECNamedCurveSpec params = new ECNamedCurveSpec(ECC_CURVE_NAME, ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN(), ecCurve.getH());

        // Convert the key Bytes into a BigInteger, then create the Private Key from it.
        BigInteger s = new BigInteger(1, keyBytes);
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, params);
        return (ECPrivateKey) kf.generatePrivate(keySpec);
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
