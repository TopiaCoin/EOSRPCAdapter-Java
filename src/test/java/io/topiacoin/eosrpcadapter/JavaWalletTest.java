package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import io.topiacoin.eosrpcadapter.util.EOSByteWriter;
import io.topiacoin.eosrpcadapter.util.EOSKeysUtil;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.util.TextUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FilenameFilter;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import static junit.framework.TestCase.*;

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

        String chainID = "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f";

        String walletName = "test-" + System.currentTimeMillis();
        wallet.create(walletName) ;

        String privateKeyWif1 = wallet.createKey();
        wallet.importKey(walletName, privateKeyWif1) ;
        String privateKeyWif2 = wallet.createKey();
        wallet.importKey(walletName, privateKeyWif2) ;

        List<String> keys = wallet.getPublicKeys(walletName) ;

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));

        Map<String, Object> args = new HashMap<String, Object>();
        args.put("user", "inita");
        args.put("guid", 81985529216486894L);
        args.put("workspaceDescription", "A Different Description");
        List<String> scopes = new ArrayList<String>();
        scopes.add("active");
        List<Transaction.Authorization> authorizations = new ArrayList<Transaction.Authorization>();
        authorizations.add(new Transaction.Authorization("inita", "active"));
        Date expirationDate = new Date(System.currentTimeMillis() + 60000) ;
        Transaction transaction = eosrpcAdapter.chain().createRawTransaction("inita", "update",
                args, scopes, authorizations, expirationDate);

        String publicKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV";
        String privateKey = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

        wallet.importKey(walletName, privateKey);

        keys.clear();
        keys.add(publicKey);

        SignedTransaction signedTransaction;
        {
            signedTransaction = wallet.signTransaction(transaction, keys, chainID);
            System.out.println(signedTransaction);
            String actualSignature = signedTransaction.signatures.get(0);
            System.out.println("JavaWallet Signature: " + actualSignature);

            // Calculate the Message Signature Hash
            byte[] digest = digest(signedTransaction, chainID);

            // See if we can recover the public key
            String recoveredKey = EOSKeysUtil.recoverPublicKey(actualSignature, digest);

            System.out.println("Expected Public Key : " + publicKey);
            System.out.println("Recovered Public Key: " + recoveredKey);
            assertEquals(publicKey, recoveredKey);
        }


        SignedTransaction signedTransaction2;
        {
            signedTransaction2 = eosrpcAdapter.wallet().signTransaction(transaction, keys, chainID);
            System.out.println(signedTransaction2);
            String actualSignature2 = signedTransaction2.signatures.get(0);
            System.out.println("RPC Wallet Signature: " + actualSignature2);

            // Calculate the Message Signature Hash
            byte[] digest = digest(signedTransaction, chainID);

            // See if we can recover the public key
            String recoveredKey = EOSKeysUtil.recoverPublicKey(actualSignature2, digest);

            System.out.println("Expected Public Key : " + publicKey);
            System.out.println("Recovered Public Key: " + recoveredKey);
//            assertEquals(publicKey, recoveredKey);
        }


        // Attempt to push the transaction
        Chain chain = eosrpcAdapter.chain();
        Transaction.Response response = chain.pushTransaction(signedTransaction);

        assertNotNull(response.transaction_id);
        assertTrue (!TextUtils.isEmpty(response.transaction_id ));
    }


    private byte[] digest (SignedTransaction transaction, String chainID) throws Exception {
        EOSByteWriter eosByteWriter = new EOSByteWriter(10240);
        byte[] chainIDBytes = Hex.decodeHex(chainID.toCharArray());

        transaction.pack(eosByteWriter);
        byte[] packedTxBytes = eosByteWriter.toBytes();

        ByteBuffer buffer = ByteBuffer.allocate(10240) ;
        buffer.put(chainIDBytes) ;
        buffer.put(packedTxBytes);
        buffer.put(new byte[32]);
        buffer.flip();

        byte[] data = new byte[buffer.remaining()] ;
        buffer.get(data);

        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);

        System.out.println ( "Recovery Digest: "+ Hex.encodeHexString(digest));

        return digest;
    }
}
