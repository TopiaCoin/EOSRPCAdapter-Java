package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.exceptions.KeyException;
import io.topiacoin.eosrpcadapter.exceptions.SignatureException;
import io.topiacoin.eosrpcadapter.exceptions.WalletException;
import io.topiacoin.eosrpcadapter.messages.Keys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import io.topiacoin.eosrpcadapter.util.Base58;
import io.topiacoin.eosrpcadapter.util.EOSByteWriter;
import io.topiacoin.eosrpcadapter.util.EOSKeysUtil;
import io.topiacoin.eosrpcadapter.util.HMacDSAKCalculator2;
import org.apache.commons.codec.DecoderException;
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
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeMap;

public class JavaWallet implements Wallet {

    private final Log _log = LogFactory.getLog(this.getClass());

    private static final String DEFAULT_WALLET_NAME = "default";
    private static final int DEFAULT_WALLET_TIMEOUT = 15 * 60 * 1000; // 15 minutes

    private final Timer _lockTimer = new Timer("walletLockTimer");
    private final Map<String, TimerTask> _walletLockTasks= new HashMap<String, TimerTask>();

    private Map<String, EOSWallet> _eosWallets;

    public JavaWallet() {
        _eosWallets = new HashMap<String, EOSWallet>();
    }

    @Override
    public String createKey() throws WalletException {
        String newKeyWif = null ;

        try {
            ECPrivateKey newKey = EOSKeysUtil.generateECPrivateKey();
            newKeyWif = EOSKeysUtil.encodeAndCheckPrivateKey(newKey);
        } catch (KeyException e) {
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
        } catch (KeyException e) {
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
            e.printStackTrace();
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
        } catch (KeyException e) {
            _log.warn ( "Failed to import key to specified wallet: " + walletName, e) ;
        } catch (IOException e) {
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
        return signTransaction(transaction, keys, "");
    }

    @Override
    public SignedTransaction signTransaction(Transaction transaction, List<String> keys, String chainID) throws WalletException {

        List<String> remainingKeys = new ArrayList<String>(keys);
        List<String> signatureList = new ArrayList<String>();

        try {
            byte[] digest = getSigDigest(transaction, chainID);

            for ( EOSWallet wallet : _eosWallets.values() ) {
                Iterator<String> keyItr = remainingKeys.iterator();
                while ( keyItr.hasNext()) {
                    String key = keyItr.next();
                    String signature = wallet.signDigest(digest, key) ;
                    if ( signature != null ) {
                        signatureList.add(signature);
                        keyItr.remove();
                    }
                }
            }
        } catch (DecoderException e) {
            throw new WalletException("Unable to sign Transaction: Invalid Chain ID", e);
        } catch (ParseException e) {
            throw new WalletException("Unable to sign Transaction: Invalid Chain ID", e);
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Unable to sign Transaction: Invalid Chain ID", e);
        } catch (KeyException e) {
            throw new WalletException("Unable to sign Transaction: Invalid Chain ID", e);
        } catch (SignatureException e) {
            throw new WalletException("Unable to sign Transaction: Invalid Chain ID", e);
        }

        SignedTransaction signedTransaction = new SignedTransaction(transaction, signatureList);

        return signedTransaction;
    }

    public byte[] getSigDigest(Transaction transaction, String chainID) throws DecoderException, ParseException, NoSuchAlgorithmException {
        EOSByteWriter eosByteWriter = new EOSByteWriter(10240);
        byte[] chainIDBytes = Hex.decodeHex(chainID.toCharArray());

        // Reverse the chain ID Bytes to Little Endian.
        byte[] temp = new byte[chainIDBytes.length] ;
        for ( int i = 0 ; i < chainIDBytes.length ; i++ ){
            temp[temp.length - i - 1] = chainIDBytes[i] ;
        }
//        chainIDBytes = temp;

        eosByteWriter.putBytes(chainIDBytes, chainIDBytes.length);
        transaction.pack(eosByteWriter);

        // Context Free Data
        if ( transaction.context_free_data.size() > 0 ) {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            for (String str : transaction.context_free_data) {
                sha256.update(str.getBytes());
            }
            byte[] cfdHash = sha256.digest();
            eosByteWriter.putBytes(cfdHash, cfdHash.length); // CFD Hash
        } else {
            eosByteWriter.putBytes(new byte[32], 32);
        }

        byte[] packedBytes = eosByteWriter.toBytes();

        System.out.println ( "Data to Sign: " + Hex.encodeHexString(packedBytes));

        // Digest the packed bytes
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] digest = sha256.digest(packedBytes);

        System.out.println ( "Digest : " + Hex.encodeHexString(digest));
        return digest;
    }

    @Override
    public URL getWalletURL() {
        URL walletURL = null;

        try {
            walletURL = new URL("wallet://java");
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        return walletURL;
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

    static class EOSWallet {
        public static final String SIG_PREFIX = "SIG_K1_";
        private long _lockTimeout;
        private String _wallet_filename;
        private Map<String,String> _keys;
        private byte[] _checksum;
        private WalletData _wallet;  // -> Contains cipher_keys

        public static EOSWallet createWallet(String name, String password) throws NoSuchAlgorithmException, IOException {
            EOSWallet wallet = new EOSWallet();

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = sha512.digest(password.getBytes());

            wallet._wallet_filename = name + ".wallet";
            wallet._checksum = hashBytes;

            try {
                wallet.importKey("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3");
            } catch (KeyException e) {
                throw new IOException("Failed to add default key to wallet", e);
            } catch (WalletException e) {
                throw new IOException("Failed to add default key to wallet", e);
            }
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

        public String createKey() throws WalletException, KeyException, IOException {
            if ( isLocked() ) {
                throw new WalletException("Wallet is Locked") ;
            }
            String publicKeyWif = null;
            String privateKeyWif = null;

            // Crate the new Private Key
            ECPrivateKey privateKey = EOSKeysUtil.generateECPrivateKey();
            ECPublicKey publicKey = EOSKeysUtil.getPublicKeyFromPrivateKey(privateKey);

            // Obtain the public and private keys in WIF format
            publicKeyWif = EOSKeysUtil.encodeAndCheckPublicKey(publicKey);
            privateKeyWif = EOSKeysUtil.encodeAndCheckPrivateKey(privateKey);

            // Store the keys in the map
            _keys.put(publicKeyWif, privateKeyWif);

            // Pack, Encrypt, and Save the wallet to disk
            updateWalletCipherKeys();
            saveWallet();

            return publicKeyWif;
        }

        public String importKey(String privateKeyWif) throws WalletException, KeyException, IOException {
            if ( isLocked() ) {
                throw new WalletException("Wallet is Locked") ;
            }

                // Obtain the Public Key for the given private key and convert it to WIF format
                ECPublicKey publicKey = EOSKeysUtil.checkAndDecodePublicKeyFromPrivateKeyString(privateKeyWif);
                String publicKeyWif = EOSKeysUtil.encodeAndCheckPublicKey(publicKey);

                // Store the keys in the map
                _keys.put(publicKeyWif, privateKeyWif);

                // Pack, Encrypt, and Save the wallet to disk
                updateWalletCipherKeys();
                saveWallet();

                return publicKeyWif;
        }

        public void removeKey(String publicKeyWif) throws WalletException, IOException {
            if ( isLocked() ) {
                throw new WalletException("Wallet is Locked") ;
            }

            // Remove the key from the key map
            _keys.remove(publicKeyWif) ;

            // Pack, Encrypt, and Save the wallet to disk
            updateWalletCipherKeys();
            saveWallet();
        }

        public String signDigest(byte[] digest, String publicKeyWif) throws WalletException, KeyException, SignatureException {
            String signature = null;

            if (!_keys.containsKey(publicKeyWif)) {
                return null;
            }

            String privateKeyWif = _keys.get(publicKeyWif);
            System.out.println( "privateKey : " + privateKeyWif);
            ECPrivateKey privateKey = EOSKeysUtil.checkAndDecodePrivateKey(privateKeyWif);

            ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(EOSKeysUtil.ECC_CURVE_NAME);
            ECDomainParameters curve = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),
                    params.getH());

            ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator2(new SHA256Digest()));
            ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKey.getS(), curve);
            signer.init(true, privKey);

            BigInteger r;
            BigInteger s;
            do {
                BigInteger[] components;
                components = signer.generateSignature(digest);

                r = components[0];
                s = components[1];

                // Canonicalize the signature so that the S value is in the bottom half of the curve order.
                if ( s.compareTo(curve.getN().shiftRight(1)) > 0 ) {
                    s = curve.getN().subtract(s);
                }

                int i = 0;
                while (i < 4) {
                    String testSig = EOSKeysUtil.encodeAndCheckSignature(r, s, (byte) i);
                    String recoveredKey = EOSKeysUtil.recoverPublicKey(testSig, digest);
                    if (publicKeyWif.equals(recoveredKey)) {
                        signature = testSig;
                        break;
                    }
                    i++;
                }
            } while ( !EOSKeysUtil.isCanonical(r, s) ) ;

            return signature;
        }


        public boolean verifySignature(byte[] digest, String signature, String publicKeyWif) throws WalletException, KeyException {
            if (isLocked()) {
                throw new WalletException("Wallet is Locked");
            }

            EOSKeysUtil.SignatureComponents signatureComponents = EOSKeysUtil.checkAndDecodeSignature(signature);

            byte[] xBytes = Base58.decode(publicKeyWif.substring(3));
            xBytes = Arrays.copyOfRange(xBytes, 0, xBytes.length - 4);

            ECNamedCurveParameterSpec paramsSpec = ECNamedCurveTable.getParameterSpec(EOSKeysUtil.ECC_CURVE_NAME);
            ECDomainParameters curve = new ECDomainParameters(
                    paramsSpec.getCurve(),
                    paramsSpec.getG(),
                    paramsSpec.getN(),
                    paramsSpec.getH());

            boolean verified = false;

            BigInteger r = signatureComponents.r;
            BigInteger s = signatureComponents.s;

            ECDSASigner signer = new ECDSASigner();
            ECPublicKeyParameters params = new ECPublicKeyParameters(curve.getCurve().decodePoint(xBytes), curve);
            signer.init(false, params);
            try {
                verified = signer.verifySignature(digest, r, s);
            } catch (NullPointerException ex) {
                // Bouncy Castle contains a bug that can cause NPEs given specially crafted signatures. Those signatures
                // are inherently invalid/attack sigs so we just fail them here rather than crash the thread.
                ex.printStackTrace();
            }

            return verified;
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

        private byte[] packWallet() throws IOException {
            byte NULL_BYTE = (byte) 0x00;
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            buffer.put(_checksum);
            buffer.put((byte)_keys.size());
            for ( Map.Entry<String, String> entry : _keys.entrySet() ) {
                byte[] publicBytes = new byte[0];
                byte[] privateBytes = new byte[0];
                try {
                    publicBytes = EOSKeysUtil.checkAndDecodePublicKeyBytes(entry.getKey());
                    privateBytes = EOSKeysUtil.checkAndDecodePrivateKeyBytes(entry.getValue());
                } catch (KeyException e) {
                    throw new IOException("Exception packing the wallet", e);
                }
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

        private EOSWallet unpackWallet(byte[] decryptedWalletBytes) throws IOException {
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
                String wifPubKey = null;
                String wifPrivKey = null;
                try {
                    wifPubKey = EOSKeysUtil.encodeAndCheckPublicKeyBytes(pubKey, true);
                    wifPrivKey = EOSKeysUtil.encodeAndCheckPrivateKeyBytes(privKey, true);
                } catch (KeyException e) {
                    throw new IOException("Exception unpacking the wallet", e);
                }

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
