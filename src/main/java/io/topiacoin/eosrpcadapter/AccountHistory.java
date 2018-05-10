package io.topiacoin.eosrpcadapter;

import java.net.URL;

public class AccountHistory {

    private final URL chainURL ;
    private final EOSRPCAdapter rpcAdapter;

    AccountHistory(URL chainURL, EOSRPCAdapter rpcAdapter) {
        this.chainURL = chainURL;
        this.rpcAdapter = rpcAdapter;
    }

    public void getTransaction(String transactionID) {

    }

    public void getTransactions(String accountName) {

    }

    public void getKeyAccounts(String publicKey) {

    }

    public void getControlledAccounts(String accountName) {

    }

    // -------- Accessor Methods --------


    public URL getChainURL() {
        return chainURL;
    }
}
