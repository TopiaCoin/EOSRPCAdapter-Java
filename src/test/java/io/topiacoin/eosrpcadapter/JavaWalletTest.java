package io.topiacoin.eosrpcadapter;

import org.junit.AfterClass;

import java.io.File;
import java.io.FilenameFilter;

public class JavaWalletTest extends AbstractWalletTests {
    @Override
    protected Wallet getWallet() {
        JavaWallet wallet = new JavaWallet();

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
