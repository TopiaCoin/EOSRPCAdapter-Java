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

    boolean open(String name) throws WalletException;

    String create(String name) throws WalletException;

    boolean lock(String name) throws WalletException;

    boolean unlock(String name,
                   String password) throws WalletException;

    boolean lockAll() throws WalletException;

    List<String> getPublicKeys(String name) throws WalletException;

    Keys listKeys(String name,
                  String password) throws WalletException;

    boolean importKey(String name,
                      String key) throws WalletException;

    boolean setTimeout(String name, int timeoutSecs) throws WalletException;

    SignedTransaction signTransaction(Transaction transaction,
                                      List<String> keys) throws WalletException;

    SignedTransaction signTransaction(Transaction transaction,
                                      List<String> keys,
                                      String chainID) throws WalletException;

    URL getWalletURL();
}
