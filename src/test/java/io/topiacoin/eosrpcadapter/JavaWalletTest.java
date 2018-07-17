package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import io.topiacoin.eosrpcadapter.util.EOSKeysUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FilenameFilter;
import java.net.URL;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JavaWalletTest extends AbstractWalletTests {

    @BeforeClass
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

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

    @Test
    public void testSigningTransaction() throws Exception {
        Wallet wallet = getWallet();
        URL nodeURL = new URL("http://localhost:8888/");
        URL walletURL = new URL("http://localhost:8899/");
        EOSRPCAdapter eosrpcAdapter = new EOSRPCAdapter(nodeURL, walletURL);

        String walletName = "test-" + System.currentTimeMillis();
        wallet.create(walletName) ;

        String privateKeyWif1 = wallet.createKey();
        wallet.importKey(walletName, privateKeyWif1) ;
        String privateKeyWif2 = wallet.createKey();
        wallet.importKey(walletName, privateKeyWif2) ;

        List<String> keys = wallet.getPublicKeys(walletName) ;

        Map<String, Object> args = new HashMap<String, Object>();
        args.put("owner", "inita");
        args.put("guid", 0x123456789abcdefL);
        args.put("workspaceName", "bar");
        args.put("workspaceDescription", "fooz");
        args.put("key", "shh.secret");
        List<String> scopes = new ArrayList<String>();
        scopes.add("active");
        List<Transaction.Authorization> authorizations = new ArrayList<Transaction.Authorization>();
        authorizations.add(new Transaction.Authorization("inita", "active"));
        Date expirationDate = new Date(System.currentTimeMillis() + 60000);
        Transaction transaction = eosrpcAdapter.chain().createRawTransaction("inita", "create",
                args, scopes, authorizations, expirationDate);

        SignedTransaction signedTransaction = wallet.signTransaction(transaction, keys) ;

        System.out.println ( signedTransaction );
    }

}
