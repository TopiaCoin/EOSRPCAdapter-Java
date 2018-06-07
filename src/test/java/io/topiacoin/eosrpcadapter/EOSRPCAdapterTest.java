package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.messages.AbiBinToJson;
import io.topiacoin.eosrpcadapter.messages.AbiJsonToBin;
import io.topiacoin.eosrpcadapter.messages.GetAccount;
import io.topiacoin.eosrpcadapter.messages.GetBlock;
import io.topiacoin.eosrpcadapter.messages.GetCode;
import io.topiacoin.eosrpcadapter.messages.GetInfo;
import io.topiacoin.eosrpcadapter.messages.GetRequiredKeys;
import io.topiacoin.eosrpcadapter.messages.GetTableRows;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;
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
        args.put("owner", "inita");
        args.put("guid", "0x123456789");
        args.put("workspaceName", "Foo");

        AbiJsonToBin.Response response = chain.abiJsonToBin("inita", "create", args);

        assertNotNull(response);
    }

    @Test
    public void testChainAbiBinToJson() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        AbiBinToJson.Response response = chain.abiBinToJson("inita", "create", "000000000093dd748967452301000000000000000000000003466f6f");

        assertNotNull(response);

        System.out.println("Args: " + response.args);
    }

    @Test
    public void testChainPushTransaction() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        Map args = new HashMap();
        args.put("owner", "inita");
        args.put("guid", "0x123456789");
        args.put("workspaceName", "Foo");

        Date expDate = new Date(System.currentTimeMillis() + 60000);

        Transaction transaction = null;
        List<String> scope = Arrays.asList("inita");
        Transaction.Authorization authorization = new Transaction.Authorization();
        authorization.account="inita";
        authorization.permission="active";
        List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
        transaction = chain.createRawTransaction("inita", "create", args, scope, authorizations, expDate);

        Transaction.Response response = chain.pushTransaction(transaction);

        assertNotNull(response);
    }

    @Test
    public void testChainPushTransactions() throws Exception {

    }

    @Test
    public void testChainGetRequiredKeys() throws Exception {
        EOSRPCAdapter adapter = getEosRPCAdapter();
        Chain chain = adapter.chain();

        Map args = new HashMap();
        args.put("owner", "inita");
        args.put("guid", "0x123456789");
        args.put("workspaceName", "Foo");

        Date expDate = new Date(System.currentTimeMillis() + 60000);

        Transaction transaction = null;
        List<String> scope = Arrays.asList("inita");
        Transaction.Authorization authorization = new Transaction.Authorization();
        authorization.account="inita";
        authorization.permission="active";
        List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
        transaction = chain.createRawTransaction("inita", "create", args, scope, authorizations, expDate);

        String[] availableKeys = new String[]{
                "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
                "EOS6js37ofHj5Tf3DsGiSuwjA1BrkyuhMaoChhwtGhKdRRGUuXBvu",
                "EOS7NjEaNA9GGyK8W7nuH4NHiq9i4C8AuHYcsRijqfQrypfjMC36M"};

        GetRequiredKeys.Response response = chain.getRequiredKeys(transaction, availableKeys);

        assertNotNull(response);
    }

}
