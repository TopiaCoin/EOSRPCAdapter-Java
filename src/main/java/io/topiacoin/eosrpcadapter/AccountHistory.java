package io.topiacoin.eosrpcadapter;

public interface AccountHistory {
    void getTransaction(String transactionID);

    void getTransactions(String accountName);

    void getKeyAccounts(String publicKey);

    void getControlledAccounts(String accountName);
}
