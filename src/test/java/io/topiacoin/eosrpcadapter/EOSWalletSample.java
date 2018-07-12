package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.util.Base58;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.asymmetric.ec.EC5Util;
import org.bouncycastle.jce.provider.asymmetric.ec.ECUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class EOSWalletSample {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String walletName = "/Users/john/eosio-wallet/default";
        String password = "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1";

        // Load the Wallet
        Wallet wallet = Wallet.loadWallet(walletName);

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

        System.out.println( "Locked  : " + wallet ) ;

        // Save the Wallet
        wallet.saveWallet();

        // Create a brand new wallet
        String newPassword = EOSKeysUtil.generateRandomPassword();
        wallet = Wallet.createWallet("sample", newPassword);

        System.out.println( "New      : " + wallet ) ;

        // Create a Key in the Wallet
        String publicKey = wallet.createKey();

        System.out.println( "With Key : " + wallet ) ;

        // Import a Key into the Wallet
        String newPubKey = null; // EOS8agBfR3DABrBc8Pj38nyby41QW3xPJWGHmvfP9dzde9ZfsqZhb
        String newPrivKey = "5HzsKHxUK6s75jv66j5MNNLkLrWQt6Ng4MYWhbmfKwqUHk4sNgy";
        newPubKey = wallet.importKey(newPrivKey);

        System.out.println( "Import   : " + wallet ) ;

        // Load and Unlock the new wallet
        wallet = Wallet.loadWallet("sample");
        wallet.unlock(newPassword);

        System.out.println( "UnLocked : " + wallet ) ;

        // List the Public Keys in the Wallet
        List<String> publicKeys = wallet.listPublicKeys() ;

        System.out.println ( "Public Keys: " + publicKeys);

        // List the Private Keys in the Wallet
        List<List<String>> privateKeys = wallet.listPrivateKeys() ;

        System.out.println ( "Private Keys: " + privateKeys);

        // Remove Key from the Wallet
        wallet.removeKey(newPubKey) ;

        System.out.println ( "Removed   : " + wallet ) ;

        // TODO - Sign with the Wallet
        byte[] digest = "foobarbazfizzbuz".getBytes() ;
        String signature = wallet.signDigest(digest, publicKey) ;

        System.out.println("Signature : " + signature);

        // TODO - Verify Signature with the Wallet
        boolean verified = wallet.verifySignature(digest, signature, publicKey);

        System.out.println ("Verified : " + verified);

        String recoveredKey = EOSKeysUtil.recoverPublicKey(signature, digest);

        System.out.println("Expected Key : " + publicKey);
        System.out.println("Recovered Key : " + recoveredKey);
    }

    private static class Wallet {
        public String _wallet_filename;
        public Map<String,String> _keys;
        public byte[] _checksum;
        public WalletData _wallet;  // -> Contains cipher_keys

        public static Wallet createWallet(String name, String password) throws Exception {
            Wallet wallet = new Wallet();

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = sha512.digest(password.getBytes());

            wallet._wallet_filename = name + ".wallet";
            wallet._checksum = hashBytes;

            wallet.updateWalletCipherKeys();
            wallet.saveWallet();

            return wallet;
        }

        public static Wallet loadWallet(String walletName) throws Exception {
            File walletFile = new File (walletName + ".wallet");

            if ( !walletFile.exists() || !walletFile.isFile()) {
                throw new FileNotFoundException("The Specified Wallet could not be loaded");
            }

            ObjectMapper objectMapper = new ObjectMapper();

            WalletData walletData  = objectMapper.readValue(walletFile, WalletData.class);
            Wallet wallet = new Wallet();
            wallet._wallet = walletData;
            wallet._wallet_filename = walletFile.getName();
            return wallet;
        }

        private Wallet() {
            _keys = new TreeMap<String, String>();
            _wallet = new WalletData();
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
            updateWalletCipherKeys();

            // Clear out the decrypted data
            _keys = null;
            _checksum = null;
        }

        public boolean isLocked() {
            return _checksum == null;
        }

        public String createKey() throws Exception {
            if ( isLocked() ) {
                throw new RuntimeException("Wallet is Locked") ;
            }
            String publicKeyWif = null;
            String privateKeyWif = null;

            // Crate the new Private Key
            ECPrivateKey privateKey = EOSKeysUtil.generateECPrivateKey();
            ECPublicKey publicKey = EOSKeysUtil.getPublicKeyFromPrivateKey(privateKey);

            // Obtain the public and private keys in WIF format
            publicKeyWif = EOSKeysUtil.publicKeyToWif(publicKey);
            privateKeyWif = EOSKeysUtil.privateKeyToWif(privateKey);

            // Store the keys in the map
            _keys.put(publicKeyWif, privateKeyWif);

            // Pack, Encrypt, and Save the wallet to disk
            updateWalletCipherKeys();
            saveWallet();

            return publicKeyWif;
        }

        public String importKey(String privateKeyWif) throws Exception {
            if ( isLocked() ) {
                throw new RuntimeException("Wallet is Locked") ;
            }

            // Obtain the Public Key for the given private key and convert it to WIF format
            ECPublicKey publicKey = EOSKeysUtil.getPublicKeyFromPrivateString(privateKeyWif) ;
            String publicKeyWif = EOSKeysUtil.publicKeyToWif(publicKey);

            // Store the keys in the map
            _keys.put(publicKeyWif, privateKeyWif) ;

            // Pack, Encrypt, and Save the wallet to disk
            updateWalletCipherKeys();
            saveWallet();

            return publicKeyWif;
        }

        public void removeKey(String publicKeyWif) throws Exception {
            if ( isLocked() ) {
                throw new RuntimeException("Wallet is Locked") ;
            }

            // Remove the key from the key map
            _keys.remove(publicKeyWif) ;

            // Pack, Encrypt, and Save the wallet to disk
            updateWalletCipherKeys();
            saveWallet();
        }

        public String signDigest(byte[] digest, String publicKeyWif) throws Exception {
            if ( isLocked() ) {
                throw new RuntimeException("Wallet is Locked") ;
            }

            String signature = null;

            String privateKeyWif = _keys.get(publicKeyWif) ;
            ECPrivateKey privateKey = EOSKeysUtil.getPrivateKeyFromPrivateString(privateKeyWif);
            ECPublicKey publicKey = EOSKeysUtil.getPublicKeyFromPublicString(publicKeyWif);

            Signature signature1 = Signature.getInstance("ECDSA");
            signature1.initSign(privateKey);
            signature1.update(digest);
            byte[] sigBytes = signature1.sign();

            System.out.println("publicKey : " + publicKeyWif);
            byte recID = 0;
            while ( recID < 4 ) {
                signature = EOSKeysUtil.asn1SigToWif(sigBytes, publicKey, recID);
                String recoverPublicKey = EOSKeysUtil.recoverPublicKey(signature, digest);
                System.out.println ( "recID : " + signature + " -> " + recoverPublicKey) ;
                if ( recoverPublicKey.equals(publicKeyWif))
                {
                    break;
                }
                recID++;
            }

            return signature;
        }

        public boolean verifySignature(byte[] digest, String signature, String publicKeyWif) throws Exception {
            if (isLocked()) {
                throw new RuntimeException("Wallet is Locked");
            }

            boolean verified = false;
            byte[] sigBytes = EOSKeysUtil.wifSigToAsn1(signature);

            ECPublicKey publicKey = EOSKeysUtil.getPublicKeyFromPublicString(publicKeyWif);
            Signature signature1 = Signature.getInstance("ECDSA");
            signature1.initVerify(publicKey);
            signature1.update(digest);
            verified = signature1.verify(sigBytes);

            return verified;
        }


        public List<String> listPublicKeys() throws Exception {
            if ( isLocked() ) {
                throw new RuntimeException("Wallet is Locked") ;
            }

            List<String> publicKeys = new ArrayList<String>(_keys.keySet()) ;

            return publicKeys;
        }

        public List<List<String>> listPrivateKeys() throws Exception {
            if ( isLocked() ) {
                throw new RuntimeException("Wallet is Locked") ;
            }

            List<List<String>> privateKeys = new ArrayList<List<String>>() ;

            for ( Map.Entry<String,String> keyEntry : _keys.entrySet()) {
                List<String> entryList = new ArrayList<String>();
                entryList.add(keyEntry.getKey()) ;
                entryList.add(keyEntry.getValue()) ;
                privateKeys.add(entryList);
            }

            return privateKeys;
        }

        private void updateWalletCipherKeys() throws Exception {
            byte[] packedBytes = packWallet() ;

            // Encrypt the packed Bytes and update the Wallet Data
            SecretKey key = new SecretKeySpec(_checksum, 0, 32, "AES");
            IvParameterSpec ivParams = new IvParameterSpec(_checksum, 32, 16);

            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding") ;
            aes.init(Cipher.ENCRYPT_MODE, key, ivParams);

            byte[] encryptedBytes = aes.doFinal(packedBytes) ;
            String walletBytes = Hex.encodeHexString(encryptedBytes) ;
            _wallet.cipher_keys = walletBytes;
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
            for ( int i = 0 ; i < keyPairCount ; i++ ){
                decryptedByteBuffer.get();
                byte[] pubKey = new byte[33]; // Compression Header included
                byte[] privKey = new byte[32];
                decryptedByteBuffer.get(pubKey) ;
                decryptedByteBuffer.get();
                decryptedByteBuffer.get(privKey);
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

        private static class WalletData {
            public String cipher_keys;

            @Override
            public String toString() {
                return "WalletData{" +
                        "cipher_keys=" + cipher_keys +
                        '}';
            }
        }
    }

    private static class EOSKeysUtil {

        public static final String ECC_CURVE_NAME = "secp256k1";

        public static String privateKeyToWif(ECPrivateKey privateKey) throws Exception {
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

        public static ECPrivateKey generateECPrivateKey() throws Exception {
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

        public static String generateRandomPassword() throws Exception {
            String password = null;

            SecureRandom secureRandom = new SecureRandom();

            byte[] passwordEntropy = new byte[128];
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] passwordBytes = sha256.digest(passwordEntropy);

            password = "PW" + Base58.encode(passwordBytes) ;

            return password;
        }

        public static String recoverPublicKey(String signature, byte[] digest) throws Exception {
            String publicKeyWif = null;

            byte[] sigBytes = Base58.decode(signature);
            if ( sigBytes.length != 65 ) {
                throw new RuntimeException("Invalid Signature Length" );
            }
            byte i = sigBytes[0];
            if ( (i - 27) == (i - 27 & 7) ) {
//                throw new RuntimeException ("Invalid Signature Parameter");
            }
            byte[] rBytes = Arrays.copyOfRange(sigBytes, 1, 33);
            byte[] sBytes = Arrays.copyOfRange(sigBytes, 33, sigBytes.length);

            BigInteger e = new BigInteger(1, digest);

            byte i2 = i ;
            i2 -= 27;
            i2 = (byte)(i2 & 3);

            ECNamedCurveParameterSpec ecCurve = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);

            BigInteger n = ecCurve.getN();
            ECPoint G = ecCurve.getG();

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

// FIXME - When isSecondKey is true, x is outside the range of the curve!!
            BigInteger x = (isSecondKey ? r.add(n) : r);

            ECCurve ec = ecCurve.getCurve();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(ec, new byte[0]);
            ECField field = ellipticCurve.getField();

            BigInteger a = ec.getA().toBigInteger();
            BigInteger b = ec.getB().toBigInteger();
            BigInteger p = ((java.security.spec.ECFieldFp) field).getP();
            BigInteger pOverFour = p.add(BigInteger.ONE).shiftRight(2);

            BigInteger alpha = x.pow(3).add(a.multiply(x)).add(b).mod(p);
            BigInteger beta = alpha.modPow(pOverFour, p);

            BigInteger y = beta;
            if ( !beta.testBit(0) ^ !isYOdd ) {
                y = p.subtract(y);
            }

            ECPoint R = ec.createPoint(x, y, false);

            ECPoint nR = R.multiply(n);
            if ( ! nR.isInfinity() ) {
                throw new RuntimeException("nR is not a valid curve point");
            }

            BigInteger eNeg = e.negate().mod(n);

            BigInteger rInv = r.modInverse(n);

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
            }
            if ( s.length == 33 && s[0] == 0x00) {
                s = Arrays.copyOfRange(s, 1, s.length);
            }

            byte i = (byte)(27 + 4 + recID) ;
            ByteBuffer wifSigBuffer = ByteBuffer.allocate(1024);
            wifSigBuffer.put(i);
            wifSigBuffer.put(r);
            wifSigBuffer.put(s);
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
}
