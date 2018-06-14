package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.messages.AccountInfo;
import io.topiacoin.eosrpcadapter.messages.BlockInfo;
import io.topiacoin.eosrpcadapter.messages.ChainInfo;
import io.topiacoin.eosrpcadapter.messages.Code;
import io.topiacoin.eosrpcadapter.messages.Keys;
import io.topiacoin.eosrpcadapter.messages.RequiredKeys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.TableRows;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import io.topiacoin.eosrpcadapter.messages.TransactionBinArgs;
import io.topiacoin.eosrpcadapter.messages.TransactionJSONArgs;
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
    public void testChainGetInfo() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        ChainInfo response = chain.getInfo();

        assertNotNull(response);
    }

    @Test
    public void testChainGetBlock() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        BlockInfo response = chain.getBlock("1");

        assertNotNull(response);
    }

    @Test
    public void testChainGetAccount() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        AccountInfo response = chain.getAccount("inita");

        assertNotNull(response);
    }

    @Test
    public void testChainGetCode() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        Code response = chain.getCode("inita");

        assertNotNull(response);
    }


    @Test
    public void testChainGetTableRows() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        TableRows response = chain.getTableRows("sampledb", "sampledb", "workspace", -1, true);

        assertNotNull(response);
    }

    @Test
    public void testChainAbiJsonToBin() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        Map<String,String> args = new HashMap<String,String>();
        args.put("from", "inita");
        args.put("type", "foo");
        args.put("data", "bar");

        TransactionBinArgs response = chain.abiJsonToBin("inita", "anyaction", args);

        assertNotNull(response);
    }

    @Test
    public void testChainAbiBinToJson() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        TransactionJSONArgs response = chain.abiBinToJson("inita", "anyaction", "000000000093dd7403666f6f03626172");

        assertNotNull(response);

        System.out.println("Args: " + response.args);
    }

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

        List<String> publicKeys = wallet.getPublicKeys();

        RequiredKeys response = chain.getRequiredKeys(transaction, publicKeys);

        assertNotNull(response);
    }


    // ======== Wallet API Tests ========

    @Test
    public void testWalletList() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        List<String> response = wallet.list();

        assertNotNull(response);
    }

    @Test
    public void testWalletOpen() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        boolean response = wallet.open("default");

        assertTrue(response);
    }

    @Test
    public void testWalletCreate() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        String walletName = "test-" + System.currentTimeMillis();

        String response = wallet.create(walletName);

        assertNotNull(response);
    }

    @Test
    public void testWalletLockUnlockLockAll() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        String walletName = "test-" + System.currentTimeMillis();

        String password = wallet.create(walletName);
        assertNotNull(password);

        List<String> listResponse = wallet.list();
        assertNotNull(listResponse);

        boolean unlockResponse = wallet.unlock(walletName, password);
        assertTrue(unlockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);

        boolean lockResponse = wallet.lock(walletName);
        assertTrue(lockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);

        unlockResponse = wallet.unlock(walletName, password);
        assertTrue(unlockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);

        lockResponse = wallet.lockAll();
        assertTrue(lockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);
    }

    @Test
    public void testWalletImportListAndGetPublicKeys() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        String walletName = "test-" + System.currentTimeMillis();

        // Lock all Wallets
        wallet.lockAll();

        // Create a new wallet
        String password = wallet.create(walletName);
        assertNotNull(password);

        // Unlock the new wallet
        boolean unlockResponse = wallet.unlock(walletName, password);
        assertTrue(unlockResponse);

        // List Public Keys in Wallet
        List<String> publicKeys = wallet.getPublicKeys();
        assertNotNull(publicKeys);
        assertEquals(1, publicKeys.size());

        // List Keys in wallet
        Keys keysResponse = wallet.listKeys(walletName, password);
        assertNotNull(keysResponse);
        assertNotNull(keysResponse.keys);
        assertEquals(1, keysResponse.keys.size());

        // Create new EOS key
        String privateKey = wallet.createKey();
        assertNotNull (privateKey) ;

        // Import Key into Wallet
        boolean importResponse = wallet.importKey(walletName, privateKey);
        assertTrue(importResponse);

        // List Public Keys in Wallet
        publicKeys = wallet.getPublicKeys();
        assertNotNull(publicKeys);
        assertEquals(2, publicKeys.size());

        // List Keys in wallet
        keysResponse = wallet.listKeys(walletName, password);
        assertNotNull(keysResponse);
        assertNotNull(keysResponse.keys);
        assertEquals(2, keysResponse.keys.size());
    }

    @Test
    public void testWalletSetTimeout() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        boolean response = wallet.setTimeout(3600);

        assertTrue(response);
    }

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

        List<String> publicKeys = wallet.getPublicKeys();

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

        List<String> publicKeys = wallet.getPublicKeys();

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


        List<String> publicKeys = wallet.getPublicKeys();

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
