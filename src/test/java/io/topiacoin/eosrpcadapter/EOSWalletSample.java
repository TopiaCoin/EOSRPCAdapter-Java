package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.util.Base58;
import io.topiacoin.eosrpcadapter.util.EOSKeysUtil;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
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
        EOSWallet wallet = EOSWallet.loadWallet(walletName);

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
        wallet = EOSWallet.createWallet("sample", newPassword);

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
        wallet = EOSWallet.loadWallet("sample");
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
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        String message = "foobarbazfizzbuzz";
        byte[] digest = sha256.digest(message.getBytes()) ;
        String signature = wallet.signDigest(digest, publicKey) ;

        System.out.println ( "Message : " + message ) ;
        System.out.println("Signature : " + signature);

        // TODO - Verify Signature with the Wallet
        boolean verified = wallet.verifySignature(digest, signature, publicKey);

        System.out.println ("Verified : " + verified);

        String recoveredKey = EOSKeysUtil.recoverPublicKey(signature, digest);
        String recoveredKey2 = EOSKeysUtil.recoverPublicKey2(signature, digest);

        System.out.println("Expected Key   : " + publicKey);
        System.out.println("Recovered Key  : " + recoveredKey);
        System.out.println("Recovered Key2 : " + recoveredKey2);


        byte[] data = Hex.decodeHex("c321495bd814694e29be0000000001000000000093dd7400000000a86c52d501000000000093dd7400000000a8ed323228000000000093dd74eecdab8967452301174120446966666572656e74204465736372697074696f6e00".toCharArray()) ;
        byte[] digest2 = sha256.digest(data);

        String sig = "KkKmcPCFEPzodA73Un87Fb9MZ494MHH4BsmciRccC2Bue8ynvMVkcxD5PbAaRTmfCexouGJAiQkqZWAH9RCYR4tfUg2rux" ;
        String pubKey = "EOS7RCvxemGXsQHmo9JZZXNvjbKY2PL5WZV98Vt9xSNy6q68eB9k1" ;

        String recoveredKey3 = EOSKeysUtil.recoverPublicKey(sig, digest) ;
        System.out.println ( "Expected Key 3 : " + pubKey);
        System.out.println ( "Recovered Key3 : " + recoveredKey3);
    }

    private static class EOSWallet {
        public String _wallet_filename;
        public Map<String,String> _keys;
        public byte[] _checksum;
        public WalletData _wallet;  // -> Contains cipher_keys

        public static EOSWallet createWallet(String name, String password) throws Exception {
            EOSWallet wallet = new EOSWallet();

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = sha512.digest(password.getBytes());

            wallet._wallet_filename = name + ".wallet";
            wallet._checksum = hashBytes;

            wallet.updateWalletCipherKeys();
            wallet.saveWallet();

            return wallet;
        }

        public static EOSWallet loadWallet(String walletName) throws Exception {
            File walletFile = new File (walletName + ".wallet");

            if ( !walletFile.exists() || !walletFile.isFile()) {
                throw new FileNotFoundException("The Specified Wallet could not be loaded");
            }

            ObjectMapper objectMapper = new ObjectMapper();

            WalletData walletData  = objectMapper.readValue(walletFile, WalletData.class);
            EOSWallet wallet = new EOSWallet();
            wallet._wallet = walletData;
            wallet._wallet_filename = walletFile.getName();
            return wallet;
        }

        private EOSWallet() {
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
            EOSWallet unpackedWallet = unpackWallet(decryptedWalletBytes);
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
            String signature = null;

            String privateKeyWif = _keys.get(publicKeyWif) ;
            ECPrivateKey privateKey = EOSKeysUtil.getPrivateKeyFromPrivateString(privateKeyWif);
            ECPublicKey publicKey = EOSKeysUtil.getPublicKeyFromPublicString(publicKeyWif);

            ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(EOSKeysUtil.ECC_CURVE_NAME);
            ECDomainParameters curve = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),
                    params.getH());

            ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
            ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKey.getS(), curve);
            signer.init(true, privKey);

            BigInteger[] components = signer.generateSignature(digest) ;

            BigInteger r = components[0];
            BigInteger s = components[1];

            // Compile r and s into a signature string along with the calculated i.
            byte[] rBytes = r.toByteArray();
            byte[] sBytes = s.toByteArray();
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
            byte[] sigBytes = new byte[asn1Buffer.remaining()];
            asn1Buffer.get(sigBytes);

            int i = 0 ;
            while ( i < 4 ) {
                String testSig = EOSKeysUtil.asn1SigToWif(sigBytes, publicKey, (byte)i++);
                String recoveredKey = EOSKeysUtil.recoverPublicKey(testSig, digest);
                if ( publicKeyWif.equals(recoveredKey)) {
                    signature = testSig;
                    break;
                }
            }
            return signature;
        }


        public boolean verifySignature(byte[] digest, String signature, String publicKeyWif) throws Exception {
            if (isLocked()) {
                throw new RuntimeException("Wallet is Locked");
            }

            PublicKey publicKey = EOSKeysUtil.getPublicKeyFromPublicString(publicKeyWif) ;
            byte[] xBytes = Base58.decode(publicKeyWif.substring(3));
            xBytes = Arrays.copyOfRange(xBytes, 0, xBytes.length - 4);

            ECNamedCurveParameterSpec paramsSpec = ECNamedCurveTable.getParameterSpec(EOSKeysUtil.ECC_CURVE_NAME);
            ECDomainParameters curve = new ECDomainParameters(
                    paramsSpec.getCurve(),
                    paramsSpec.getG(),
                    paramsSpec.getN(),
                    paramsSpec.getH());
            ECPoint G = paramsSpec.getG();
            BigInteger n = paramsSpec.getN();
            BigInteger e = new BigInteger(1, digest);

            boolean verified = false;
            byte[] sigBytes = Base58.decode(signature);
            ByteBuffer sigBuffer = ByteBuffer.wrap(sigBytes);
            byte[] rBytes = new byte[32];
            byte[] sBytes = new byte[32];
            sigBuffer.get() ;
            sigBuffer.get(rBytes);
            sigBuffer.get(sBytes);

            BigInteger r = new BigInteger(1, rBytes) ;
            BigInteger s = new BigInteger(1, sBytes) ;

            ECDSASigner signer = new ECDSASigner();
            ECPublicKeyParameters params = new ECPublicKeyParameters(curve.getCurve().decodePoint(xBytes), curve);
            signer.init(false, params);
            try {
                return signer.verifySignature(digest, r, s);
            } catch (NullPointerException ex) {
                // Bouncy Castle contains a bug that can cause NPEs given specially crafted signatures. Those signatures
                // are inherently invalid/attack sigs so we just fail them here rather than crash the thread.
                ex.printStackTrace();
                return false;
            }
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

        private EOSWallet unpackWallet(byte[] decryptedWalletBytes) throws Exception {
            EOSWallet tempWallet = new EOSWallet();
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

}
