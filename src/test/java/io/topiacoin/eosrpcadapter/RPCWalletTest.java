package io.topiacoin.eosrpcadapter;

import java.net.MalformedURLException;
import java.net.URL;

public class RPCWalletTest extends AbstractWalletTests {
    @Override
    protected Wallet getWallet() {
        URL nodeURL = null;
        URL walletURL = null;
        try {
            nodeURL = new URL("http://localhost:8888/");
            walletURL = new URL("http://localhost:8899/");

            EOSRPCAdapter eosrpcAdapter = new EOSRPCAdapter(nodeURL, walletURL);

            RPCWallet wallet = new RPCWallet(walletURL, eosrpcAdapter);

            return wallet;
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
}
