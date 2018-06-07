package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.messages.Transaction;

import java.net.URL;

public class Wallet {

    private final EOSRPCAdapter rpcAdapter;
    private final URL walletURL ;

    Wallet(URL walletURL, EOSRPCAdapter rpcAdapter) {
        this.walletURL = walletURL;
        this.rpcAdapter = rpcAdapter;
    }

    public void list() {

    }

    public void lockAll() {

    }

    public void getPublicKeys() {

    }

    public void listKeys() {

    }

    public void create(String name) {

    }

    public void open(String name) {

    }

    public void lock(String name) {

    }

    public void unlock(String name, String password) {

    }

    public void importKey(String name, String key) {

    }

    public void setTimeout(int timeoutSecs) {

    }

    public void signTransaction (Transaction transaction, String[] keys) {

    }

    public void signTransaction (Transaction transaction, String[] keys, String chainID) {

    }

    // -------- Accessor Methods --------


    public URL getWalletURL() {
        return walletURL;
    }
}
