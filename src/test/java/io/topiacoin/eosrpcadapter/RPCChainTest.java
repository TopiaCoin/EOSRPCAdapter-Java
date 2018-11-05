package io.topiacoin.eosrpcadapter;

import java.net.MalformedURLException;
import java.net.URL;

public class RPCChainTest extends AbstractChainTests {

    @Override
    protected Chain getChain() {
        return getChain("127.0.0.1");
    }

    @Override
    protected Chain getChain(String hostname) {
        URL nodeURL = null;
        URL walletURL = null;
        try {
            nodeURL = new URL("http://"+hostname+":8888/");
            walletURL = new URL("http://"+hostname+":8899/");

            EOSRPCAdapter eosrpcAdapter = new EOSRPCAdapter(nodeURL, walletURL);

            RPCChain chain = new RPCChain(nodeURL, eosrpcAdapter);

            return chain;
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
}
