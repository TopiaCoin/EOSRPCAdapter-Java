package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.exceptions.WalletException;
import io.topiacoin.eosrpcadapter.messages.Keys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import io.topiacoin.eosrpcadapter.util.Base58;
import io.topiacoin.eosrpcadapter.util.EOSKeysUtil;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeMap;

public class JKSWallet implements Wallet {

    private final Log _log = LogFactory.getLog(this.getClass());

    private static final String DEFAULT_WALLET_NAME = "default";
    private static final int DEFAULT_WALLET_TIMEOUT = 900000; // 15 minutes

    private final Timer _lockTimer = new Timer("walletLockTimer");
    private final Map<String, TimerTask> _walletLockTasks= new HashMap<String, TimerTask>();

    private Map<String, EOSWallet> _eosWallets;

    public JKSWallet() {
        _eosWallets = new HashMap<String, EOSWallet>();
    }

    @Override
    public String createKey() throws WalletException {
        String newKeyWif = null ;

        try {
            ECPrivateKey newKey = EOSKeysUtil.generateECPrivateKey();
            newKeyWif = EOSKeysUtil.privateKeyToWif(newKey);
        } catch (NoSuchProviderException e) {
            throw new WalletException("Unable to load the required Security Provider", e) ;
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Unable to find the required encryption algorithms", e) ;
        } catch (InvalidKeySpecException e) {
            throw new WalletException("Unable to create new key", e);
        }

        return newKeyWif;
    }

    @Override
    public List<String> list() throws WalletException {
        return new ArrayList<String>(_eosWallets.keySet());
    }

    @Override
    public boolean open(String name) throws WalletException {
        if (name == null) {
            name = DEFAULT_WALLET_NAME;
        }
        try {
            EOSWallet wallet = _eosWallets.get(name);
            if (wallet == null) {
                wallet = EOSWallet.loadWallet(name);
                wallet._lockTimeout = DEFAULT_WALLET_TIMEOUT;
                _eosWallets.put(name, wallet);
            }
            return (wallet != null);
        } catch (IOException e) {
            throw new WalletException("Failed to load the specified wallet: " + name, e);
        }
    }

    @Override
    public String create(String walletName) throws WalletException {
        if (walletName == null) {
            walletName = DEFAULT_WALLET_NAME;
        }

        String password = null;
        try {
            password = EOSKeysUtil.generateRandomPassword();
            EOSWallet wallet = EOSWallet.createWallet(walletName, password);
            wallet._lockTimeout = DEFAULT_WALLET_TIMEOUT;
            _eosWallets.put(walletName, wallet);
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Failed to create new wallet: " + walletName, e);
        } catch ( IOException e) {
            throw new WalletException("Failed to create new wallet: " + walletName, e);
        }

        return password;
    }

    @Override
    public boolean lock(String walletName) throws WalletException {
        if (walletName == null) {
            walletName = DEFAULT_WALLET_NAME;
        }

        if (!_eosWallets.containsKey(walletName)) {
            throw new WalletException("The specified wallet does not exist: " + walletName);
        }

        try {
            EOSWallet walletData = _eosWallets.get(walletName);

            walletData.lock();

            TimerTask task = _walletLockTasks.remove(walletName);
            if ( task != null ) {
                task.cancel();
            }
        } catch (IOException e) {
            return false;
        }

        return true;
    }

    @Override
    public boolean unlock(String walletName, String password) throws WalletException {
        if (walletName == null) {
            walletName = DEFAULT_WALLET_NAME;
        }

        if (!_eosWallets.containsKey(walletName)) {
            throw new WalletException("The specified wallet does not exist: " + walletName);
        }

        try {
            EOSWallet walletData = _eosWallets.get(walletName);

            walletData.unlock(password);

            TimerTask task = new WalletAutoLockTask(walletData) ;
            _lockTimer.schedule(task, walletData._lockTimeout);
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    @Override
    public boolean lockAll() throws WalletException {

        boolean allLocked = true ;

        for ( EOSWallet walletData : _eosWallets.values()) {
            try {
                walletData.lock();
            } catch (IOException e) {
                allLocked = false ;
            }
        }

        _walletLockTasks.clear();
        _lockTimer.purge();

        return allLocked;
    }

    @Override
    public List<String> getPublicKeys(String name) throws WalletException {
        if ( name == null ) {
            name = DEFAULT_WALLET_NAME;
        }

        if ( !_eosWallets.containsKey(name)) {
            throw new WalletException("The specified wallet does not exist");
        }

        List<String> publicKeys = null ;

        EOSWallet walletData = _eosWallets.get(name);

        publicKeys = walletData.listPublicKeys() ;

        return publicKeys;
    }

    @Override
    public Keys listKeys(String walletName, String password) throws WalletException {
        if ( walletName == null ) {
            walletName = DEFAULT_WALLET_NAME;
        }

        if ( !_eosWallets.containsKey(walletName)) {
            throw new WalletException("The specified wallet does not exist");
        }

        List<List<String>> keyPairsList = null ;

        EOSWallet walletData = _eosWallets.get(walletName);

        keyPairsList = walletData.listPrivateKeys() ;

        Keys keys = new Keys();
        keys.keys = new ArrayList<Keys.KeyPair>();
        for ( List<String> keyPairList : keyPairsList) {
            String publicKey = keyPairList.get(0);
            String privateKey = keyPairList.get(1);
            Keys.KeyPair keyPair = new Keys.KeyPair(publicKey, privateKey) ;
            keys.keys.add(keyPair);
        }
        return keys;
    }

    @Override
    public boolean importKey(String walletName, String key) throws WalletException {
        if ( walletName == null ) {
            walletName = DEFAULT_WALLET_NAME;
        }

        if ( !_eosWallets.containsKey(walletName)) {
            throw new WalletException("The specified wallet does not exist");
        }

        boolean imported = false ;

        EOSWallet walletData = _eosWallets.get(walletName);

        try {
            walletData.importKey(key);
            imported = true;
        } catch ( WalletException e ) {
            _log.warn ( "Failed to import key to specified wallet: " + walletName, e) ;
        }

        return imported;
    }

    @Override
    public boolean setTimeout(String walletName, int timeoutSecs) throws WalletException {

        if ( walletName == null ) {
            walletName = DEFAULT_WALLET_NAME;
        }

        if ( !_eosWallets.containsKey(walletName)) {
            throw new WalletException("The specified wallet does not exist");
        }

        EOSWallet walletData = _eosWallets.get(walletName);
        walletData._lockTimeout = timeoutSecs * 1000 ;

        if ( !walletData.isLocked()) {
            TimerTask task = _walletLockTasks.remove(walletName);
            if ( task != null ) {
                task.cancel();
            }
            task = new WalletAutoLockTask(walletData) ;
            _lockTimer.schedule(task, walletData._lockTimeout);
        }

        return true;
    }

    @Override
    public SignedTransaction signTransaction(Transaction transaction, List<String> keys) throws WalletException {
        return null;
    }

    @Override
    public SignedTransaction signTransaction(Transaction transaction, List<String> keys, String chainID) throws WalletException {
        return null;
    }

    @Override
    public URL getWalletURL() {
        return null;
    }

    // -------- AutoLock Timer Class --------

    private static class WalletAutoLockTask extends TimerTask {

        private final EOSWallet wallet;

        public WalletAutoLockTask(EOSWallet wallet) {
            this.wallet = wallet;
        }

        /**
         * The action to be performed by this timer task.
         */
        @Override
        public void run() {
            try {
                System.out.println ( "Auto Lock Executing");
                wallet.lock();
            } catch (IOException e) {
                // NOOP
                e.printStackTrace();
            }
        }
    }

    // -------- EOS Wallet Class --------

    private static class EOSWallet {
        public long _lockTimeout;
        public String _wallet_filename;
        public Map<String,String> _keys;
        public byte[] _checksum;
        public WalletData _wallet;  // -> Contains cipher_keys

        public static EOSWallet createWallet(String name, String password) throws NoSuchAlgorithmException, IOException {
            EOSWallet wallet = new EOSWallet();

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = sha512.digest(password.getBytes());

            wallet._wallet_filename = name + ".wallet";
            wallet._checksum = hashBytes;

            wallet.updateWalletCipherKeys();
            wallet.saveWallet();

            return wallet;
        }

        public static EOSWallet loadWallet(String walletName) throws IOException {
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

        public void saveWallet() throws IOException {
            File walletFile = new File(_wallet_filename);

            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.writeValue(walletFile, _wallet);
        }

        public void unlock(String password) throws WalletException {
            try {
                byte[] passwordBytes = password.getBytes("UTF-8");

                MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                byte[] hashBytes = sha512.digest(passwordBytes);
                SecretKey key = new SecretKeySpec(hashBytes, 0, 32, "AES");
                IvParameterSpec ivParams = new IvParameterSpec(hashBytes, 32, 16);

                Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aes.init(Cipher.DECRYPT_MODE, key, ivParams);

                byte[] walletBytes = Hex.decodeHex(_wallet.cipher_keys.toCharArray());
                byte[] decryptedWalletBytes = aes.doFinal(walletBytes);

                // Unpack decrypted wallet
                EOSWallet unpackedWallet = unpackWallet(decryptedWalletBytes);
                if (!Arrays.equals(unpackedWallet._checksum, hashBytes)) {
                    throw new RuntimeException("Password was not correct");
                }
                _checksum = unpackedWallet._checksum;
                _keys = unpackedWallet._keys;
            } catch (Exception e) {
                throw new WalletException("Failed to unloack Wallet", e) ;
            }
        }

        public void lock() throws IOException {
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
                throw new WalletException("Wallet is Locked") ;
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

        public String importKey(String privateKeyWif) throws WalletException {
            if ( isLocked() ) {
                throw new WalletException("Wallet is Locked") ;
            }

            try {
                // Obtain the Public Key for the given private key and convert it to WIF format
                ECPublicKey publicKey = EOSKeysUtil.getPublicKeyFromPrivateString(privateKeyWif);
                String publicKeyWif = EOSKeysUtil.publicKeyToWif(publicKey);

                // Store the keys in the map
                _keys.put(publicKeyWif, privateKeyWif);

                // Pack, Encrypt, and Save the wallet to disk
                updateWalletCipherKeys();
                saveWallet();

                return publicKeyWif;
            } catch ( Exception e ) {
                throw new WalletException("Failed to import the specified Key", e);
            }
        }

        public void removeKey(String publicKeyWif) throws Exception {
            if ( isLocked() ) {
                throw new WalletException("Wallet is Locked") ;
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
                throw new WalletException("Wallet is Locked");
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

        public List<String> listPublicKeys() throws WalletException {
            if ( isLocked() ) {
                throw new WalletException("Wallet is Locked") ;
            }

            List<String> publicKeys = new ArrayList<String>(_keys.keySet()) ;

            return publicKeys;
        }

        public List<List<String>> listPrivateKeys() throws WalletException {
            if ( isLocked() ) {
                throw new WalletException("Wallet is Locked") ;
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

        // -------- Private Methods --------

        private void updateWalletCipherKeys() throws IOException {
            byte[] packedBytes = packWallet() ;

            try {
                // Encrypt the packed Bytes and update the Wallet Data
                SecretKey key = new SecretKeySpec(_checksum, 0, 32, "AES");
                IvParameterSpec ivParams = new IvParameterSpec(_checksum, 32, 16);

                Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aes.init(Cipher.ENCRYPT_MODE, key, ivParams);

                byte[] encryptedBytes = aes.doFinal(packedBytes);
                String walletBytes = Hex.encodeHexString(encryptedBytes);
                _wallet.cipher_keys = walletBytes;
            } catch (NoSuchAlgorithmException e) {
                throw new IOException("Failed to encrypt wallet", e) ;
            } catch (InvalidKeyException e) {
                throw new IOException("Failed to encrypt wallet", e) ;
            } catch (InvalidAlgorithmParameterException e) {
                throw new IOException("Failed to encrypt wallet", e) ;
            } catch (NoSuchPaddingException e) {
                throw new IOException("Failed to encrypt wallet", e) ;
            } catch (BadPaddingException e) {
                throw new IOException("Failed to encrypt wallet", e) ;
            } catch (IllegalBlockSizeException e) {
                throw new IOException("Failed to encrypt wallet", e) ;
            }
        }

        private byte[] packWallet() {
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

        private EOSWallet unpackWallet(byte[] decryptedWalletBytes) throws NoSuchAlgorithmException {
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
