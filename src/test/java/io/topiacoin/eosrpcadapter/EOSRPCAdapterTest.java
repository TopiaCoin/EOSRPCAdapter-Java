package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.messages.AbiBinToJson;
import io.topiacoin.eosrpcadapter.messages.AbiJsonToBin;
import io.topiacoin.eosrpcadapter.messages.CreateKey;
import io.topiacoin.eosrpcadapter.messages.CreateWallet;
import io.topiacoin.eosrpcadapter.messages.GetAccount;
import io.topiacoin.eosrpcadapter.messages.GetBlock;
import io.topiacoin.eosrpcadapter.messages.GetCode;
import io.topiacoin.eosrpcadapter.messages.GetInfo;
import io.topiacoin.eosrpcadapter.messages.GetRequiredKeys;
import io.topiacoin.eosrpcadapter.messages.GetTableRows;
import io.topiacoin.eosrpcadapter.messages.ImportKey;
import io.topiacoin.eosrpcadapter.messages.ListKeys;
import io.topiacoin.eosrpcadapter.messages.ListPublicKeys;
import io.topiacoin.eosrpcadapter.messages.ListWallets;
import io.topiacoin.eosrpcadapter.messages.LockWallet;
import io.topiacoin.eosrpcadapter.messages.OpenWallet;
import io.topiacoin.eosrpcadapter.messages.SetTimeout;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import io.topiacoin.eosrpcadapter.messages.UnlockWallet;
import org.junit.Ignore;
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

        GetInfo.Response response = chain.getInfo();

        assertNotNull(response);
    }

    @Test
    public void testChainGetBlock() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        GetBlock.Response response = chain.getBlock("1");

        assertNotNull(response);
    }

    @Test
    public void testChainGetAccount() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        GetAccount.Response response = chain.getAccount("inita");

        assertNotNull(response);
    }

    @Test
    public void testChainGetCode() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        GetCode.Response response = chain.getCode("inita");

        assertNotNull(response);
    }


    @Test
    public void testChainGetTableRows() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        GetTableRows.Response response = chain.getTableRows("inita", "inita", "workspace", true);

        assertNotNull(response);
    }

    @Test
    public void testChainAbiJsonToBin() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        Map args = new HashMap();
        args.put("from", "inita");
        args.put("type", "foo");
        args.put("data", "bar");

        AbiJsonToBin.Response response = chain.abiJsonToBin("inita", "anyaction", args);

        assertNotNull(response);
    }

    @Test
    public void testChainAbiBinToJson() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        AbiBinToJson.Response response = chain.abiBinToJson("inita", "anyaction", "000000000093dd7403666f6f03626172");

        assertNotNull(response);

        System.out.println("Args: " + response.args);
    }

    @Test
    public void testChainGetRequiredKeys() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();
        Wallet wallet = adapter.wallet();

        UnlockWallet.Response unlockResponse = wallet.unlock("default", "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1");

        Map args = new HashMap();
        args.put("from", "inita");
        args.put("type", "foo");
        args.put("data", "bar");

        Date expDate = new Date(System.currentTimeMillis() + 60000);

        Transaction transaction = null;
        List<String> scope = Arrays.asList("inita");
        Transaction.Authorization authorization = new Transaction.Authorization();
        authorization.actor="inita";
        authorization.permission="active";
        List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
        transaction = chain.createRawTransaction("inita", "anyaction", args, scope, authorizations, expDate);

        List<String> publicKeys = wallet.getPublicKeys().publicKeys;;

        GetRequiredKeys.Response response = chain.getRequiredKeys(transaction, publicKeys);

        assertNotNull(response);
    }


    // ======== Wallet API Tests ========

    @Test
    public void testWalletList() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        ListWallets.Response response = wallet.list();

        assertNotNull(response);
    }

    @Test
    public void testWalletOpen() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        OpenWallet.Response response = wallet.open("default");

        assertNotNull(response);
    }

    @Test
    public void testWalletCreate() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        String walletName = "test-" + System.currentTimeMillis();

        CreateWallet.Response response = wallet.create(walletName);

        assertNotNull(response);
    }

    @Test
    public void testWalletLockUnlockLockAll() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        String walletName = "test-" + System.currentTimeMillis();
        String password ;

        CreateWallet.Response createResponse = wallet.create(walletName);
        assertNotNull(createResponse);
        password = createResponse.password;

        ListWallets.Response listResponse = wallet.list();
        assertNotNull(listResponse);

        UnlockWallet.Response unlockResponse = wallet.unlock(walletName, password);
        assertNotNull(unlockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);

        LockWallet.Response lockResponse = wallet.lock(walletName);
        assertNotNull(lockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);

        unlockResponse = wallet.unlock(walletName, password);
        assertNotNull(unlockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);

        lockResponse = wallet.lockAll();
        assertNotNull(lockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);
    }

    @Test
    public void testWalletImportListAndGetPublicKeys() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        String walletName = "test-" + System.currentTimeMillis();
        String password ;

        // Lock all Wallets
        wallet.lockAll();

        // Create a new wallet
        CreateWallet.Response createResponse = wallet.create(walletName);
        assertNotNull(createResponse);
        password = createResponse.password;

        // Unlock the new wallet
        UnlockWallet.Response unlockResponse = wallet.unlock(walletName, password);

        // Create keypair
        CreateKey.Response createKeyResponse = wallet.createKey();
        String privateKey = createKeyResponse.eosKey;

        // Import Key into Wallet
        ImportKey.Response importResponse = wallet.importKey(walletName, privateKey);

        // List Public Keys in Wallet
        ListPublicKeys.Response pubKeyResponse = wallet.getPublicKeys();

        // List Keys in wallet
        ListKeys.Response keysResponse = wallet.listKeys();
    }

    @Test
    public void testWalletSetTimeout() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Wallet wallet = adapter.wallet();

        SetTimeout.Response response = wallet.setTimeout(10);

        assertNotNull(response);
    }

    @Test
    public void testWalletSignTransaction() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();
        Wallet wallet = adapter.wallet();

        // Unlock the new wallet
        UnlockWallet.Response unlockResponse = wallet.unlock("default", "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1");

        Map args = new HashMap();
        args.put("from", "inita");
        args.put("type", "foo");
        args.put("data", "bar");

        Date expDate = new Date(System.currentTimeMillis() + 60000);

        Transaction transaction = null;
        List<String> scope = Arrays.asList("inita");
        Transaction.Authorization authorization = new Transaction.Authorization();
        authorization.actor="inita";
        authorization.permission="active";
        List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
        transaction = chain.createRawTransaction("inita", "anyaction", args, scope, authorizations, expDate);

        List<String> publicKeys = wallet.getPublicKeys().publicKeys;

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
        UnlockWallet.Response unlockResponse = wallet.unlock("default", "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1");

        Map args = new HashMap();
        args.put("from", "inita");
        args.put("type", "foo");
        args.put("data", "bar");

        Date expDate = new Date(System.currentTimeMillis() + 60000);

        GetInfo.Response chainInfo = chain.getInfo();

        Transaction transaction = null;
        List<String> scope = Arrays.asList("inita");
        Transaction.Authorization authorization = new Transaction.Authorization();
        authorization.actor="inita";
        authorization.permission="active";
        List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
        transaction = chain.createRawTransaction("inita", "anyaction", args, scope, authorizations, expDate);

        List<String> publicKeys = wallet.getPublicKeys().publicKeys;

        GetRequiredKeys.Response reqKeyResponse = chain.getRequiredKeys(transaction, publicKeys);

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
        UnlockWallet.Response unlockResponse = wallet.unlock("default", "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1");

        Date expDate = new Date(System.currentTimeMillis() + 60000);

        GetInfo.Response chainInfo = chain.getInfo();

        Transaction transaction1 = null;
        {
            Map args = new HashMap();
            args.put("from", "inita");
            args.put("type", "foo");
            args.put("data", "bar");

            List<String> scope = Arrays.asList("inita");
            Transaction.Authorization authorization = new Transaction.Authorization();
            authorization.actor = "inita";
            authorization.permission = "active";
            List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
            transaction1 = chain.createRawTransaction("inita", "anyaction", args, scope, authorizations, expDate);
        }

        Transaction transaction2 = null;
        {
            Map args = new HashMap();
            args.put("from", "inita");
            args.put("type", "fizz");
            args.put("data", "buzz");

            List<String> scope = Arrays.asList("inita");
            Transaction.Authorization authorization = new Transaction.Authorization();
            authorization.actor = "inita";
            authorization.permission = "active";
            List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
            transaction2 = chain.createRawTransaction("inita", "anyaction", args, scope, authorizations, expDate);
        }


        List<String> publicKeys = wallet.getPublicKeys().publicKeys;

        GetRequiredKeys.Response reqKey1Response = chain.getRequiredKeys(transaction1, publicKeys);
        SignedTransaction signedTransaction1 = wallet.signTransaction(transaction1, reqKey1Response.required_keys, chainInfo.chain_id) ;

        assertNotNull ( signedTransaction1 ) ;

        GetRequiredKeys.Response reqKey2Response = chain.getRequiredKeys(transaction2, publicKeys);
        SignedTransaction signedTransaction2 = wallet.signTransaction(transaction2, reqKey1Response.required_keys, chainInfo.chain_id) ;

        assertNotNull ( signedTransaction2 ) ;

        List<SignedTransaction> transactions = new ArrayList<SignedTransaction>();
        transactions.add(signedTransaction1);
        transactions.add(signedTransaction2);

        List<Transaction.Response> pushResponses = chain.pushTransactions(transactions);

        System.out.println ( "Push Response: " + pushResponses ) ;
    }
}
