package io.topiacoin.eosrpcadapter;

import java.security.KeyStoreException;

public class JKSWalletTest extends AbstractWalletTests {
    @Override
    protected Wallet getWallet() {
        JKSWallet wallet = new JKSWallet();

        return wallet;
    }
}
