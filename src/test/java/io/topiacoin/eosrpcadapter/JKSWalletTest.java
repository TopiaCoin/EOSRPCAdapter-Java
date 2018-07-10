package io.topiacoin.eosrpcadapter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;

public class JKSWalletTest extends AbstractWalletTests {
    @Override
    protected Wallet getWallet() {
        JKSWallet wallet = new JKSWallet();

        return wallet;
    }
}
