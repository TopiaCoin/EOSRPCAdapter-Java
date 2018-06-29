package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.exceptions.WalletException;
import io.topiacoin.eosrpcadapter.messages.Keys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;

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

public class JKSWallet implements Wallet {

    private static final String PW_PREFIX = "PW";

    private File walletPath ;
    private Map<String,WalletData> _wallets;

    public JKSWallet() throws KeyStoreException {

        walletPath = new File("~/.wallets/") ;
        walletPath.mkdirs();

        _wallets = new HashMap<String, WalletData>();
    }

    @Override
    public String createKey() throws WalletException {
        return null;
    }

    @Override
    public List<String> list() throws WalletException {
        return new ArrayList<String>(_wallets.keySet());
    }

    @Override
    public boolean open(String name) throws WalletException {
        WalletData wallet = _wallets.get(name);
        if (wallet == null) {
            File keyStorePath = new File(walletPath, name + ".jks");
            if (keyStorePath.exists()) {
                wallet = new WalletData(keyStorePath);
                _wallets.put(name, wallet);
            }
        }
        return (wallet != null);
    }

    @Override
    public String create(String name) throws WalletException {
        if ( _wallets.containsKey(name)) {
            throw new WalletException("A wallet with the specified name already exists", null);
        }

        String password = generatePassword() ;

        try {
            File keyStorePath = new File(walletPath, name + ".jks");
            KeyStore keyStore = KeyStore.getInstance("JKS");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            keyStore.store(baos, password.toCharArray());

            byte[] bytes = baos.toByteArray();

            WalletData walletData = new WalletData(keyStorePath, bytes);

        } catch (KeyStoreException e) {
            throw new WalletException("Unable to create the requested wallet", null);
        } catch (IOException e) {
            throw new WalletException("Unable to create the requested wallet", null);
        } catch (NoSuchAlgorithmException e) {
            throw new WalletException("Unable to create the requested wallet", null);
        } catch (CertificateException e) {
            throw new WalletException("Unable to create the requested wallet", null);
        }

        return password;
    }

    @Override
    public boolean lock(String name) throws WalletException {
        return false;
    }

    @Override
    public boolean unlock(String name, String password) throws WalletException {
        return false;
    }

    @Override
    public boolean lockAll() throws WalletException {
        return false;
    }

    @Override
    public List<String> getPublicKeys() throws WalletException {
        return null;
    }

    @Override
    public Keys listKeys(String name, String password) throws WalletException {
        return null;
    }

    @Override
    public boolean importKey(String name, String key) throws WalletException {
        return false;
    }

    @Override
    public boolean setTimeout(int timeoutSecs) throws WalletException {
        return false;
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


    // ======== Private Methods ========

    private String generatePassword() {
        String password = null ;

        password = PW_PREFIX + "";

        return password ;
    }

    // ======== Inner Classes ========

    private static class WalletData {

        private final File filePath;
        private byte[] keystoreData;
        private KeyStore keystore;

        public WalletData(File filePath) {
            this.filePath = filePath;
            load() ;
        }

        public WalletData(File keyStorePath, byte[] bytes) {
            this.filePath = keyStorePath;
            this.keystoreData = bytes;
        }

        public void unlock(String password) {

        }

        public void lock() {

        }

        public boolean isLocked() {
            return false ;
        }

        public void importKey() {

        }

        public void createKey() {

        }

        public List<PublicKey> listPublicKeys() {
            return null;
        }

        public List<PrivateKey> listPrivateKeys() {
            return null;
        }

        public void load() {

        }

        public void save() {

        }

        public File getFilePath() {
            return filePath;
        }

        public boolean checkPassword(String password) {
            return false ;
        }

        public void setPassword(String newPassword) {

        }

        public void getPrivateKey(String publicKey) {

        }
    }
}
