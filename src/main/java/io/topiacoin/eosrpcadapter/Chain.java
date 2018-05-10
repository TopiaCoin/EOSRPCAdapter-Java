package io.topiacoin.eosrpcadapter;

import java.net.URL;

public class Chain {

    private final EOSRPCAdapter rpcAdapater;
    private final URL chainURL ;

    Chain(URL chainURL, EOSRPCAdapter rpcAdapter) {
        this.chainURL = chainURL;
        this.rpcAdapater = rpcAdapter;
    }

    public void getInfo() {

    }

    public void getBlock(String blockNumOrID) {

    }

    public void getAccount(String accountName) {

    }

    public void getCode(String accountName) {

    }

    public void getTableRows(String contract, String scope, String table, boolean json) {

    }

    public void getRequiredKeys(Transaction transaction, String[] availableKeys) {

    }

    public void abiJsonToBin(String code, String action, String args) {

    }

    public void abiBinToJson(String code, String action, String binArgs) {

    }

    public void pushTransaction(Transaction signedTransaction) {

    }

    public void pushTransactions(Transaction[] signedTransactions) {

    }


    // -------- Accessor Methods --------


    public URL getChainURL() {
        return chainURL;
    }
}
