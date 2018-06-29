package io.topiacoin.eosrpcadapter;

import java.net.URL;

public class RPCAccountHistory implements AccountHistory {

    private final URL chainURL ;
    private final EOSRPCAdapter rpcAdapter;

    RPCAccountHistory(URL chainURL, EOSRPCAdapter rpcAdapter) {
        this.chainURL = chainURL;
        this.rpcAdapter = rpcAdapter;
    }

    @Override
    public void getTransaction(String transactionID) {

    }

    @Override
    public void getTransactions(String accountName) {

    }

    @Override
    public void getKeyAccounts(String publicKey) {

    }

    @Override
    public void getControlledAccounts(String accountName) {

    }

    // -------- Accessor Methods --------


    public URL getChainURL() {
        return chainURL;
    }
}
