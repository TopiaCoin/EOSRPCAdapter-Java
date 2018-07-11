package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.util.Base58;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;

public class EOSWalletSample {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String walletPath = "/Users/john/eosio-wallet/default.wallet";
        String password = "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1";

        File walletFile = new File(walletPath);

        // Load the Wallet
        Wallet wallet = Wallet.loadWallet(walletFile);

        System.out.println( "Loaded  : " + wallet ) ;

        // Unlock the Wallet
        wallet.unlock(password);

        System.out.println( "Unlocked: " + wallet ) ;

        // Access the items in the Wallet
        for ( String publicKey : wallet._keys.keySet() ) {

            String privateKey = wallet._keys.get(publicKey) ;

            // Get the Private Key from the Private Key WIF String
            ECPrivateKey ecPrivateKey = EOSKeysUtil.getPrivateKeyFromPrivateString(privateKey) ;
            System.out.println (ecPrivateKey ) ;

            // Get the Public Key from the Public Key WIF String
            ECPublicKey ecPublicKey = EOSKeysUtil.getPublicKeyFromPublicString(publicKey) ;
            System.out.println( "From Public  : " + ecPublicKey) ;

            // Get the Public Key from the *Private* Key WIF String
            ecPublicKey = EOSKeysUtil.getPublicKeyFromPrivateString(privateKey) ;
            System.out.println( "From Private : " + ecPublicKey) ;
        }

        // Lock the Wallet
        wallet.lock() ;

        // Save the Wallet
        wallet.saveWallet();

        // TODO - Sign with the Wallet

        // TODO - Verify Signature with the Wallet

        System.out.println( "Locked  : " + wallet ) ;
    }

    private static class Wallet {
        public String _wallet_filename;
        public Map<String,String> _keys;
        public byte[] _checksum;
        public WalletData _wallet;  // -> Contains cipher_keys

        public static Wallet loadWallet(File walletFile) throws Exception {
            ObjectMapper objectMapper = new ObjectMapper();

            WalletData walletData  = objectMapper.readValue(walletFile, WalletData.class);
            Wallet wallet = new Wallet();
            wallet._wallet = walletData;
            wallet._wallet_filename = walletFile.getName();
            return wallet;
        }

        public void saveWallet() throws Exception {
            File walletFile = new File(_wallet_filename);

            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.writeValue(walletFile, _wallet);
        }

        public void unlock(String password) throws Exception {
            byte[] passwordBytes = password.getBytes("UTF-8");

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = sha512.digest(passwordBytes);
            SecretKey key = new SecretKeySpec(hashBytes, 0, 32, "AES");
            IvParameterSpec ivParams = new IvParameterSpec(hashBytes, 32, 16);

            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding") ;
            aes.init(Cipher.DECRYPT_MODE, key, ivParams);

            byte[] walletBytes = Hex.decodeHex(_wallet.cipher_keys.toCharArray());
            byte[] decryptedWalletBytes = aes.doFinal(walletBytes) ;

            // Unpack decrypted wallet
            Wallet unpackedWallet = unpackWallet(decryptedWalletBytes);
            if ( !Arrays.equals(unpackedWallet._checksum, hashBytes)) {
                throw new RuntimeException("Password was not correct");
            }
            _checksum = unpackedWallet._checksum;
            _keys = unpackedWallet._keys;
        }

        public void lock() throws Exception {
            // Pack the Wallet
            byte[] packedBytes = packWallet() ;

            // Encrypt the packed Bytes and update the Wallet Data
            SecretKey key = new SecretKeySpec(_checksum, 0, 32, "AES");
            IvParameterSpec ivParams = new IvParameterSpec(_checksum, 32, 16);

            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding") ;
            aes.init(Cipher.ENCRYPT_MODE, key, ivParams);

            byte[] encryptedBytes = aes.doFinal(packedBytes) ;
            String walletBytes = Hex.encodeHexString(encryptedBytes) ;
            _wallet.cipher_keys = walletBytes;

            // Clear out the decrypted data
            _keys = null;
            _checksum = null;
        }

        public boolean isLocked() {
            return _checksum == null;
        }

        private byte[] packWallet() throws Exception {
            byte NULL_BYTE = (byte) 0x00;
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            buffer.put(_checksum);
            buffer.put((byte)_keys.size());
            for ( Map.Entry<String, String> entry : _keys.entrySet() ) {
                byte[] publicBytes = EOSKeysUtil.keyBytesFromPublicWif(entry.getKey());
                byte[] privateBytes = EOSKeysUtil.keyBytesFromPrivateWif(entry.getValue());
                buffer.put(NULL_BYTE);
                buffer.put(publicBytes);
                buffer.put(NULL_BYTE);
                buffer.put(privateBytes);
            }

            buffer.flip();
            byte[] packedBytes = new byte[buffer.remaining()] ;
            buffer.get(packedBytes);

            return packedBytes ;
        }

        private Wallet unpackWallet(byte[] decryptedWalletBytes) throws Exception {
            Wallet tempWallet = new Wallet();
            tempWallet._keys = new TreeMap<String, String>();
            ByteBuffer decryptedByteBuffer = ByteBuffer.wrap(decryptedWalletBytes);
            tempWallet._checksum = new byte[64];
            int keyPairCount;
            decryptedByteBuffer.get(tempWallet._checksum);
            keyPairCount = decryptedByteBuffer.get();
            decryptedByteBuffer.get();
            for ( int i = 0 ; i < keyPairCount ; i++ ){
                byte[] pubKey = new byte[33]; // Compression Header included
                byte[] privKey = new byte[32];
                decryptedByteBuffer.get(pubKey) ;
                decryptedByteBuffer.get();
                decryptedByteBuffer.get(privKey);
                if ( decryptedByteBuffer.hasRemaining() ) {
                    decryptedByteBuffer.get();
                }
                String wifPubKey = EOSKeysUtil.keyBytesToPublicWif(pubKey);
                String wifPrivKey = EOSKeysUtil.keyBytesToPrivateWif(privKey);

//                System.out.println ( "PubKey  : " + wifPubKey );
//                System.out.println (" PrivKey : " + wifPrivKey) ;

                tempWallet._keys.put(wifPubKey, wifPrivKey);
            }
            return tempWallet;
        }

        @Override
        public String toString() {
            return "Wallet{" +
                    "\n\t_wallet_filename='" + _wallet_filename + '\'' +
                    ", \n\t_keys=" + _keys +
                    ", \n\t_checksum=" + (_checksum != null ? Hex.encodeHexString(_checksum) : null ) +
                    ", \n\t_wallet=" + _wallet +
                    "\n}";
        }
    }

    private static class WalletData {
        public String cipher_keys;

        @Override
        public String toString() {
            return "WalletData{" +
                    "cipher_keys=" + cipher_keys +
                    '}';
        }
    }

    private static class EOSKeysUtil {

        public static final String ECC_CURVE_NAME = "secp256k1";

        private static String keyBytesToPrivateWif(byte[] privKey) throws Exception {
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

        private static String keyBytesToPublicWif(byte[] pubKey) throws Exception {
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

        public static ECPrivateKey getPrivateKeyFromPrivateString(String privateKeyWif) throws Exception {
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

        public static ECPublicKey getPublicKeyFromPrivateString(String privateKeyWif) throws Exception {
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
    }
}
