package io.topiacoin.eosrpcadapter;

import java.net.URL;

public class EOSRPCAdapter {

    private URL eosNodeURL;
    private URL eosWalletURL;

    private Wallet _wallet;
    private Chain _chain;
    private AccountHistory _accountHistory;

    public EOSRPCAdapter(URL nodeURL, URL walletURL) {
        this.eosNodeURL = nodeURL;
        this.eosWalletURL = walletURL;
    }

    public synchronized Wallet wallet() {
        if ( _wallet == null ){
            _wallet = new Wallet(eosWalletURL, this) ;
        }
        return _wallet;
    }

    public synchronized Chain chain() {
        if ( _chain == null ) {
            _chain = new Chain(eosNodeURL, this);
        }
        return _chain;
    }

    public synchronized AccountHistory accountHistory() {
        if ( _accountHistory == null ) {
            _accountHistory = new AccountHistory(eosNodeURL, this);
        }
        return _accountHistory;
    }

    // -------- Package Scoped methods for raw communication with the RPC API --------

    void getRequest (URL url ) {

    }

    void postReqeust (URL url, String rawData) {

    }

    void postRequest ( URL url, String rawData, boolean quotifyData) {

    }

    void validateRequest (int responseCode) {

    }

    // -------- Accessors Methods --------

    public void setEosNodeURL(URL eosNodeURL) {
        this.eosNodeURL = eosNodeURL;
    }

    public void setEosWalletURL(URL eosWalletURL) {
        this.eosWalletURL = eosWalletURL;
    }
}
