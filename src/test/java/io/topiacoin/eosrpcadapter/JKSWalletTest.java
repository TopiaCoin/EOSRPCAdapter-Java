package io.topiacoin.eosrpcadapter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.Test;

import java.io.File;
import java.io.FilenameFilter;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;

public class JKSWalletTest extends AbstractWalletTests {
    @Override
    protected Wallet getWallet() {
        JKSWallet wallet = new JKSWallet();

        return wallet;
    }

    @AfterClass
    public static void tearDownClass() {
        File currentDir = new File(".");

        File[] files = currentDir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.startsWith("test-") && name.endsWith(".wallet");
            }
        });

        for ( File file : files ) {
            file.delete();
        }
    }

}
