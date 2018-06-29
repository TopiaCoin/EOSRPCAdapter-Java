package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.messages.AccountInfo;
import io.topiacoin.eosrpcadapter.messages.BlockInfo;
import io.topiacoin.eosrpcadapter.messages.ChainInfo;
import io.topiacoin.eosrpcadapter.messages.Code;
import io.topiacoin.eosrpcadapter.messages.TableRows;
import io.topiacoin.eosrpcadapter.messages.TransactionBinArgs;
import io.topiacoin.eosrpcadapter.messages.TransactionJSONArgs;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.*;

public abstract class AbstractChainTests {

    protected abstract Chain getChain() ;

    @Test
    public void testChainGetInfo() throws Exception {
        Chain chain = getChain();

        ChainInfo response = chain.getInfo();

        assertNotNull(response);
    }

    @Test
    public void testChainGetBlock() throws Exception {
        Chain chain = getChain();

        BlockInfo response = chain.getBlock("154594");

        assertNotNull(response);
    }

    @Test
    public void testChainGetAccount() throws Exception {
        Chain chain = getChain();

        AccountInfo response = chain.getAccount("inita");

        assertNotNull(response);
    }

    @Test
    public void testChainGetCode() throws Exception {
        Chain chain = getChain();

        Code response = chain.getCode("inita");

        assertNotNull(response);
    }


    @Test
    public void testChainGetTableRows() throws Exception {
        Chain chain = getChain();

        TableRows response = chain.getTableRows("sampledb", "sampledb", "workspace", -1, true);

        assertNotNull(response);
    }

    @Test
    public void testChainAbiJsonToBin() throws Exception {
        Chain chain = getChain();

        Map<String,String> args = new HashMap<String,String>();
        args.put("from", "inita");
        args.put("type", "foo");
        args.put("data", "bar");

        TransactionBinArgs response = chain.abiJsonToBin("inita", "anyaction", args);

        assertNotNull(response);
    }

    @Test
    public void testChainAbiBinToJson() throws Exception {
        Chain chain = getChain();

        TransactionJSONArgs response = chain.abiBinToJson("inita", "anyaction", "000000000093dd7403666f6f03626172");

        assertNotNull(response);

        System.out.println("Args: " + response.args);
    }

}
