package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.exceptions.ChainException;
import io.topiacoin.eosrpcadapter.messages.AccountInfo;
import io.topiacoin.eosrpcadapter.messages.BlockInfo;
import io.topiacoin.eosrpcadapter.messages.ChainInfo;
import io.topiacoin.eosrpcadapter.messages.Code;
import io.topiacoin.eosrpcadapter.messages.RequiredKeys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.TableRows;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import io.topiacoin.eosrpcadapter.messages.TransactionBinArgs;
import io.topiacoin.eosrpcadapter.messages.TransactionJSONArgs;

import java.io.InputStream;
import java.util.Date;
import java.util.List;
import java.util.Map;

public interface Chain {
    ChainInfo getInfo() throws ChainException;

    BlockInfo getBlock(String blockNumOrID) throws ChainException;

    AccountInfo getAccount(String accountName) throws ChainException;

    Code getCode(String accountName) throws ChainException;

    TableRows getTableRows(String contract,
                           String scope,
                           String table,
                           long limit,
                           boolean json) throws ChainException;

    TableRows getTableRows(String contract,
                           String scope,
                           String table,
                           String lowerBound,
                           String upperBound,
                           long limit,
                           boolean json) throws ChainException;

    TableRows getTableRows(String contract,
                           String scope,
                           String table,
                           String key,
                           String lowerBound,
                           String upperBound,
                           long limit,
                           boolean json) throws ChainException;

    TransactionBinArgs abiJsonToBin(String code,
                                    String action,
                                    Map args) throws ChainException;

    TransactionJSONArgs abiBinToJson(String code,
                                     String action,
                                     String binArgs) throws ChainException;

    RequiredKeys getRequiredKeys(Transaction transaction,
                                 List<String> availableKeys) throws ChainException;

    Transaction.Response pushTransaction(SignedTransaction transaction) throws ChainException;

    List<Transaction.Response> pushTransactions(List<SignedTransaction> signedTransactions) throws ChainException;

    Transaction createRawTransaction(String account,
                                     String name,
                                     Map args,
                                     List<String> scopes,
                                     List<Transaction.Authorization> authorizations,
                                     Date expirationDate) throws ChainException;

    Transaction setContract(String account, InputStream abi, InputStream wasm) throws ChainException;

    String packTransaction(SignedTransaction transaction) throws ChainException;
}
