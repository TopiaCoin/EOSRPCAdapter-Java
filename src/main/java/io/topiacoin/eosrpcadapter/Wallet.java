package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.exceptions.WalletException;
import io.topiacoin.eosrpcadapter.messages.Keys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;

import java.net.URL;
import java.util.List;

public interface Wallet {
    String createKey() throws WalletException;

    List<String> list() throws WalletException;

    boolean open(String walletName) throws WalletException;

    String create(String walletName) throws WalletException;

    boolean lock(String walletName) throws WalletException;

    boolean unlock(String walletName,
                   String password) throws WalletException;

    boolean lockAll() throws WalletException;

    List<String> getPublicKeys(String walletName) throws WalletException;

    Keys listKeys(String walletName,
                  String password) throws WalletException;

    boolean importKey(String walletName,
                      String key) throws WalletException;

    boolean setTimeout(String walletName, int timeoutSecs) throws WalletException;

    SignedTransaction signTransaction(Transaction transaction,
                                      List<String> keys) throws WalletException;

    SignedTransaction signTransaction(Transaction transaction,
                                      List<String> keys,
                                      String chainID) throws WalletException;

    URL getWalletURL();
}
