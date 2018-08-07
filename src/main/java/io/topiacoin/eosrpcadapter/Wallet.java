package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.exceptions.WalletException;
import io.topiacoin.eosrpcadapter.messages.Keys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;

import java.net.URL;
import java.util.List;

public interface Wallet {

    /**
     *
     * @return
     * @throws WalletException
     */
    String createKey() throws WalletException;

    /**
     *
     * @return
     * @throws WalletException
     */
    List<String> list() throws WalletException;

    /**
     *
     * @param walletName
     * @return
     * @throws WalletException
     */
    boolean open(String walletName) throws WalletException;

    /**
     *
     * @param walletName
     * @return
     * @throws WalletException
     */
    String create(String walletName) throws WalletException;

    /**
     *
     * @param walletName
     * @return
     * @throws WalletException
     */
    boolean lock(String walletName) throws WalletException;

    /**
     *
     * @param walletName
     * @param password
     * @return
     * @throws WalletException
     */
    boolean unlock(String walletName,
                   String password) throws WalletException;

    /**
     *
     * @return
     * @throws WalletException
     */
    boolean lockAll() throws WalletException;

    /**
     *
     * @param walletName
     * @return
     * @throws WalletException
     */
    List<String> getPublicKeys(String walletName) throws WalletException;

    /**
     *
     * @param walletName
     * @param password
     * @return
     * @throws WalletException
     */
    Keys listKeys(String walletName,
                  String password) throws WalletException;

    /**
     *
     * @param walletName
     * @param key
     * @return
     * @throws WalletException
     */
    boolean importKey(String walletName,
                      String key) throws WalletException;

    /**
     *
     * @param walletName
     * @param timeoutSecs
     * @return
     * @throws WalletException
     */
    boolean setTimeout(String walletName, int timeoutSecs) throws WalletException;

    /**
     *
     * @param transaction
     * @param keys
     * @return
     * @throws WalletException
     */
    SignedTransaction signTransaction(Transaction transaction,
                                      List<String> keys) throws WalletException;

    /**
     *
     * @param transaction
     * @param keys
     * @param chainID
     * @return
     * @throws WalletException
     */
    SignedTransaction signTransaction(Transaction transaction,
                                      List<String> keys,
                                      String chainID) throws WalletException;

    /**
     * Returns the URL associated with this wallet.  This may the URL of the service
     * providing wallet functionality, or it may be a custom URL identifying a custom
     * internal wallet implementation.
     *
     * @return The URL of this wallet.
     */
    URL getWalletURL();
}
