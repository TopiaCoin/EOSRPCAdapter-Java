package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.messages.ChainInfo;
import io.topiacoin.eosrpcadapter.messages.RequiredKeys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static junit.framework.TestCase.*;

public class EOSRPCAdapterTest {

    private EOSRPCAdapter getEosRPCAdapter() throws MalformedURLException {
        URL nodeURL = new URL("http://localhost:8889/");
        URL walletURL = new URL("http://localhost:8899/");
        return new EOSRPCAdapter(nodeURL, walletURL);
    }

    // ======== RPC Adapter API Tests ========

    @Test
    public void testGetRequest() throws Exception {
        URL nodeURL = new URL("https://google.com");
        URL walletURL = new URL("https://google.com");
        EOSRPCAdapter adapter = new EOSRPCAdapter(nodeURL, walletURL);

        URL goodURL = new URL("https://google.com");

        EOSRPCAdapter.EOSRPCResponse response = adapter.getRequest(goodURL);

        assertNotNull(response);
        assertNotNull(response.response);
        assertNull(response.error);

        URL badURL = new URL("http://google.com/thisurldoesnotexist");

        response = adapter.getRequest(badURL);

        assertNotNull(response);
        assertNotNull(response.error);
        assertNull(response.response);
    }


    // ======== Chain API Tests ========


    @Test
    public void testChainGetRequiredKeys() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();
        Wallet wallet = adapter.wallet();

        boolean unlockResponse = wallet.unlock("default", "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1");

        Map<String,String> args = new HashMap<String,String>();
        args.put("from", "inita");
        args.put("type", "foo");
        args.put("data", "bar");

        Date expDate = new Date(System.currentTimeMillis() + 60000);

        Transaction transaction = null;
        List<String> scope = Arrays.asList("inita");
        Transaction.Authorization authorization = new Transaction.Authorization("inita", "active");
        List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
        transaction = chain.createRawTransaction("inita", "anyaction", args, scope, authorizations, expDate);
        System.out.println(transaction);

        List<String> publicKeys = wallet.getPublicKeys(null);

        RequiredKeys response = chain.getRequiredKeys(transaction, publicKeys);

        assertNotNull(response);
    }


    // ======== Wallet API Tests ========


    @Test
    public void testWalletSignTransaction() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();
        Wallet wallet = adapter.wallet();

        // Unlock the new wallet
        boolean unlockResponse = wallet.unlock("default", "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1");

        Map<String,String> args = new HashMap<String,String>();
        args.put("from", "inita");
        args.put("type", "foo");
        args.put("data", "bar");

        Date expDate = new Date(System.currentTimeMillis() + 60000);

        Transaction transaction = null;
        List<String> scope = Arrays.asList("inita");
        Transaction.Authorization authorization = new Transaction.Authorization("inita", "active");
        List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
        transaction = chain.createRawTransaction("inita", "anyaction", args, scope, authorizations, expDate);

        List<String> publicKeys = wallet.getPublicKeys(null);

        SignedTransaction signedTransaction = wallet.signTransaction(transaction, publicKeys) ;

        assertNotNull ( signedTransaction ) ;
    }

    // ======== Integration Tests ========

    @Test
    public void testFullTransactionSubmission() throws  Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();
        Wallet wallet = adapter.wallet();

        // Unlock the new wallet
        boolean unlockResponse = wallet.unlock("default", "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1");

        Map<String,String> args = new HashMap<String,String>();
        args.put("from", "inita");
        args.put("type", "foo");
        args.put("data", "bar");

        Date expDate = new Date(System.currentTimeMillis() + 60000);

        ChainInfo chainInfo = chain.getInfo();

        Transaction transaction = null;
        List<String> scope = Arrays.asList("inita");
        Transaction.Authorization authorization = new Transaction.Authorization("inita", "active");
        List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
        transaction = chain.createRawTransaction("inita", "anyaction", args, scope, authorizations, expDate);

        List<String> publicKeys = wallet.getPublicKeys(null);

        RequiredKeys reqKeyResponse = chain.getRequiredKeys(transaction, publicKeys);

        SignedTransaction signedTransaction = wallet.signTransaction(transaction, reqKeyResponse.required_keys, chainInfo.chain_id) ;

        assertNotNull ( signedTransaction ) ;

        Transaction.Response pushResponse = chain.pushTransaction(signedTransaction);

        System.out.println ( "Push Response: " + pushResponse ) ;
    }

    @Test
    public void testFullMultipleTransactionSubmission() throws  Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();
        Wallet wallet = adapter.wallet();

        // Unlock the new wallet
        boolean unlockResponse = wallet.unlock("default", "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1");

        Date expDate = new Date(System.currentTimeMillis() + 60000);

        ChainInfo chainInfo = chain.getInfo();

        Transaction transaction1 = null;
        {
            Map<String,String> args = new HashMap<String,String>();
            args.put("from", "inita");
            args.put("type", "foo");
            args.put("data", "bar");

            List<String> scope = Arrays.asList("inita");
            Transaction.Authorization authorization = new Transaction.Authorization("inita", "active");
            List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
            transaction1 = chain.createRawTransaction("inita", "anyaction", args, scope, authorizations, expDate);
        }

        Transaction transaction2 = null;
        {
            Map<String,String> args = new HashMap<String,String>();
            args.put("from", "inita");
            args.put("type", "fizz");
            args.put("data", "buzz");

            List<String> scope = Arrays.asList("inita");
            Transaction.Authorization authorization = new Transaction.Authorization("inita", "active");
            List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
            transaction2 = chain.createRawTransaction("inita", "anyaction", args, scope, authorizations, expDate);
        }


        List<String> publicKeys = wallet.getPublicKeys(null);

        RequiredKeys reqKey1Response = chain.getRequiredKeys(transaction1, publicKeys);
        SignedTransaction signedTransaction1 = wallet.signTransaction(transaction1, reqKey1Response.required_keys, chainInfo.chain_id) ;

        assertNotNull ( signedTransaction1 ) ;

        RequiredKeys reqKey2Response = chain.getRequiredKeys(transaction2, publicKeys);
        SignedTransaction signedTransaction2 = wallet.signTransaction(transaction2, reqKey1Response.required_keys, chainInfo.chain_id) ;

        assertNotNull ( signedTransaction2 ) ;

        List<SignedTransaction> transactions = new ArrayList<SignedTransaction>();
        transactions.add(signedTransaction1);
        transactions.add(signedTransaction2);

        List<Transaction.Response> pushResponses = chain.pushTransactions(transactions);

        System.out.println ( "Push Response: " + pushResponses ) ;
    }
}
