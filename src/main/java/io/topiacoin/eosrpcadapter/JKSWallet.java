package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.exceptions.WalletException;
import io.topiacoin.eosrpcadapter.messages.Keys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

public class JKSWallet implements Wallet {

    private static final String PW_PREFIX = "PW";
    private static final String DEFAULT_WALLET_NAME = "default";
    private static final String WALLET_EXTENSION = ".jkswallet";
    private static final int DEFAULT_WALLET_TIMEOUT = 900000; // 15 minutes

    private final Timer _lockTimer = new Timer("walletLockTimer");

    private File walletPath ;
    private Map<String,WalletData> _wallets;

    public JKSWallet() {

        String home = System.getProperty("user.home");
        walletPath = new File(home + "/.wallets/") ;
        walletPath.mkdirs();

        _wallets = new HashMap<String, WalletData>();

        // Always load the default wallet, it available.
        try {
            open(DEFAULT_WALLET_NAME);
        } catch (WalletException e) {
            // NOOP
        }
    }

    @Override
    public String createKey() throws WalletException {

        EOSKey newKey = EOSKey.randomKey();

        return newKey.toWif();
    }

    @Override
    public List<String> list() throws WalletException {
        return new ArrayList<String>(_wallets.keySet());
    }

    @Override
    public boolean open(String name) throws WalletException {
        if ( name == null ) {
            name = DEFAULT_WALLET_NAME;
        }
        WalletData wallet = _wallets.get(name);
        if (wallet == null) {
            File keyStorePath = new File(walletPath, name + WALLET_EXTENSION);
            if (keyStorePath.exists()) {
                wallet = new WalletData(keyStorePath);
                _wallets.put(name, wallet);
            }
        }
        return (wallet != null);
    }

    @Override
    public String create(String name) throws WalletException {
        if ( name == null ) {
            name = DEFAULT_WALLET_NAME;
        }

        if ( _wallets.containsKey(name)) {
            throw new WalletException("A wallet with the specified name already exists", null);
        }

        String password = generatePassword() ;

        try {
            File keyStorePath = new File(walletPath, name + WALLET_EXTENSION);
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            keyStore.store(baos, password.toCharArray());

            byte[] bytes = baos.toByteArray();

            WalletData walletData = new WalletData(keyStorePath, bytes);

            walletData.save();

            _wallets.put(name, walletData);
        } catch (KeyStoreException e) {
            throw new WalletException("Unable to create the requested wallet", e, null);
        } catch (IOException e) {
            throw new WalletException("Unable to create the requested wallet", e, null);
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Unable to create the requested wallet", e, null);
        } catch (CertificateException e) {
            throw new WalletException("Unable to create the requested wallet", e, null);
        }

        return password;
    }

    @Override
    public boolean lock(String name) throws WalletException {
        if ( name == null ) {
            name = DEFAULT_WALLET_NAME;
        }

        if ( !_wallets.containsKey(name)) {
            throw new WalletException("The specified wallet does not exist", null);
        }

        WalletData walletData = _wallets.get(name);

        walletData.lock();

        return true;
    }

    @Override
    public boolean unlock(String name, String password) throws WalletException {
        if ( name == null ) {
            name = DEFAULT_WALLET_NAME;
        }

        if ( !_wallets.containsKey(name)) {
            throw new WalletException("The specified wallet does not exist", null);
        }

        WalletData walletData = _wallets.get(name);

        boolean unlocked = walletData.unlock(password);

        return unlocked;
    }

    @Override
    public boolean lockAll() throws WalletException {

        for ( WalletData walletData : _wallets.values()) {
            walletData.lock();
        }

        return true;
    }

    @Override
    public List<String> getPublicKeys(String name) throws WalletException {
        if ( name == null ) {
            name = DEFAULT_WALLET_NAME;
        }

        if ( !_wallets.containsKey(name)) {
            throw new WalletException("The specified wallet does not exist", null);
        }

        WalletData walletData = _wallets.get(name);

        // TODO - Implement this method

        return null;
    }

    @Override
    public Keys listKeys(String name, String password) throws WalletException {
        if ( name == null ) {
            name = DEFAULT_WALLET_NAME;
        }

        if ( !_wallets.containsKey(name)) {
            throw new WalletException("The specified wallet does not exist", null);
        }

        WalletData walletData = _wallets.get(name);

        // TODO - Implement this method

        return null;
    }

    @Override
    public boolean importKey(String name, String key) throws WalletException {
        if ( name == null ) {
            name = DEFAULT_WALLET_NAME;
        }

        if ( !_wallets.containsKey(name)) {
            throw new WalletException("The specified wallet does not exist", null);
        }

        WalletData walletData = _wallets.get(name);

        EOSKey eosKey = EOSKey.fromWif(key);

        if ( eosKey == null ) {
            throw new WalletException("Invalid Key Specified", null) ;
        }

        String alias = eosKey.putPublicKey() ;
        walletData.importKey(null, eosKey.getPrivateKey());
        // TODO - Implement this method

        return false;
    }

    @Override
    public boolean setTimeout(String name, int timeoutSecs) throws WalletException {
        if ( name == null ) {
            name = DEFAULT_WALLET_NAME;
        }

        if ( !_wallets.containsKey(name)) {
            throw new WalletException("The specified wallet does not exist", null);
        }

        WalletData walletData = _wallets.get(name);

        walletData.setWalletTimeout(timeoutSecs * 1000);

        return true;
    }

    @Override
    public SignedTransaction signTransaction(Transaction transaction, List<String> keys) throws WalletException {

        // TODO - Implement this method

        return null;
    }

    @Override
    public SignedTransaction signTransaction(Transaction transaction, List<String> keys, String chainID) throws WalletException {

        // TODO - Implement this method

        return null;
    }

    @Override
    public URL getWalletURL() {
        return null;
    }


    // ======== Private Methods ========

    private String generatePassword() {
        String password = null ;

        password = PW_PREFIX + "";

        return password ;
    }

    // ======== Inner Classes ========

    private class WalletData {

        private final File filePath;
        private byte[] keystoreData;
        private KeyStore keystore;
        private String password;
        private TimerTask lockTask;

        private int walletTimeout = DEFAULT_WALLET_TIMEOUT;

        public WalletData(File filePath) {
            this.filePath = filePath;
            load() ;
        }

        public WalletData(File keyStorePath, byte[] bytes) {
            this.filePath = keyStorePath;
            this.keystoreData = bytes;
        }

        public boolean unlock(String password) {
            if ( keystoreData == null ) {
                load();
            }
            boolean unlocked = false;
            try {
                ByteArrayInputStream bais = new ByteArrayInputStream(keystoreData);
                keystore = KeyStore.getInstance("JKS");
                keystore.load(bais, password.toCharArray());
                unlocked = true ;

                    // Schedule the wallet to auto lock
                lockTask = new TimerTask() {
                    @Override
                    public void run() {
                        lock();
                    }
                };
                 _lockTimer.schedule(lockTask, walletTimeout);
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

            return unlocked;
        }

        public void lock() {
            keystore = null;

            // Cancel the TimerTask portion of the class.
            if ( lockTask != null) {
                lockTask.cancel();
                lockTask = null;
            }
        }

        public boolean isLocked() {
            return keystore == null ;
        }

        public void importKey(String alias, PrivateKey privateKey) throws WalletException{

            try {
                keystore.setKeyEntry(alias, privateKey, null, null);
            } catch (KeyStoreException e) {
                throw new WalletException("Unable to import key", e, null);
            }

            save();
        }

        public void createKey() throws WalletException{

            // TODO - Implement this method


        }

        public List<PublicKey> listPublicKeys() {

            // TODO - Implement this method

            return null;
        }

        public List<PrivateKey> listPrivateKeys() throws WalletException {

            // TODO - Implement this method

            return null;
        }

        public void load() {
            try {
                FileInputStream fis = new FileInputStream(filePath);
                ByteArrayOutputStream baos= new ByteArrayOutputStream();

                IOUtils.copy(fis, baos) ;

                keystoreData = baos.toByteArray();

                fis.close();
                baos.close();

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public void save() {
            try {
                if ( keystore != null ) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    keystore.store(baos, password.toCharArray());
                    keystoreData = baos.toByteArray();
                }

                FileOutputStream fos = new FileOutputStream(filePath);
                fos.write(keystoreData);
                fos.close();

            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public File getFilePath() {
            return filePath;
        }

        public boolean checkPassword(String password) {

            // TODO - Implement this method

            return false ;
        }

        public void setPassword(String newPassword) {

            // TODO - Implement this method

        }

        public void getPrivateKey(String publicKey) throws WalletException {

            // TODO - Implement this method

        }

        public int getWalletTimeout() {
            return walletTimeout;
        }

        public void setWalletTimeout(int walletTimeout) {
            this.walletTimeout = walletTimeout;
        }
    }
}
