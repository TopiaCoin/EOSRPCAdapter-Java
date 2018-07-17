package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.util.EOSKeysUtil;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

public class EOSWalletSample {

    public static void main(String[] args) throws Exception {

        String walletName = "/Users/john/eosio-wallet/default";
        String password = "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1";
        Security.addProvider(new BouncyCastleProvider());

        // Load the Wallet
        JavaWallet.EOSWallet wallet = JavaWallet.EOSWallet.loadWallet(walletName);

        System.out.println( "Loaded  : " + wallet ) ;

        // Unlock the Wallet
        wallet.unlock(password);

        System.out.println( "Unlocked: " + wallet ) ;

        // Access the items in the Wallet
        for ( String publicKey : wallet._keys.keySet() ) {

            String privateKey = wallet._keys.get(publicKey) ;

            // Get the Private Key from the Private Key WIF String
            ECPrivateKey ecPrivateKey = EOSKeysUtil.getPrivateKeyFromPrivateString(privateKey) ;
            System.out.println (ecPrivateKey ) ;

            // Get the Public Key from the Public Key WIF String
            ECPublicKey ecPublicKey = EOSKeysUtil.getPublicKeyFromPublicString(publicKey) ;
            System.out.println( "From Public  : " + ecPublicKey) ;

            // Get the Public Key from the *Private* Key WIF String
            ecPublicKey = EOSKeysUtil.getPublicKeyFromPrivateString(privateKey) ;
            System.out.println( "From Private : " + ecPublicKey) ;
        }

        // Lock the Wallet
        wallet.lock() ;

        System.out.println( "Locked  : " + wallet ) ;

        // Save the Wallet
        wallet.saveWallet();

        // Create a brand new wallet
        String newPassword = EOSKeysUtil.generateRandomPassword();
        wallet = JavaWallet.EOSWallet.createWallet("sample", newPassword);

        System.out.println( "New      : " + wallet ) ;

        // Create a Key in the Wallet
        String publicKey = wallet.createKey();

        System.out.println( "With Key : " + wallet ) ;

        // Import a Key into the Wallet
        String newPubKey = null; // EOS8agBfR3DABrBc8Pj38nyby41QW3xPJWGHmvfP9dzde9ZfsqZhb
        String newPrivKey = "5HzsKHxUK6s75jv66j5MNNLkLrWQt6Ng4MYWhbmfKwqUHk4sNgy";
        newPubKey = wallet.importKey(newPrivKey);

        System.out.println( "Import   : " + wallet ) ;

        // Load and Unlock the new wallet
        wallet = JavaWallet.EOSWallet.loadWallet("sample");
        wallet.unlock(newPassword);

        System.out.println( "UnLocked : " + wallet ) ;

        // List the Public Keys in the Wallet
        List<String> publicKeys = wallet.listPublicKeys() ;

        System.out.println ( "Public Keys: " + publicKeys);

        // List the Private Keys in the Wallet
        List<List<String>> privateKeys = wallet.listPrivateKeys() ;

        System.out.println ( "Private Keys: " + privateKeys);

        // Remove Key from the Wallet
        wallet.removeKey(newPubKey) ;

        System.out.println ( "Removed   : " + wallet ) ;

        // TODO - Sign with the Wallet
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        String message = "foobarbazfizzbuzz";
        byte[] digest = sha256.digest(message.getBytes()) ;
        String signature = wallet.signDigest(digest, publicKey) ;

        System.out.println ( "Message : " + message ) ;
        System.out.println("Signature : " + signature);

        // TODO - Verify Signature with the Wallet
        boolean verified = wallet.verifySignature(digest, signature, publicKey);

        System.out.println ("Verified : " + verified);

        String recoveredKey = EOSKeysUtil.recoverPublicKey(signature, digest);
        String recoveredKey2 = EOSKeysUtil.recoverPublicKey2(signature, digest);

        System.out.println("Expected Key   : " + publicKey);
        System.out.println("Recovered Key  : " + recoveredKey);
        System.out.println("Recovered Key2 : " + recoveredKey2);


        byte[] data = Hex.decodeHex("c321495bd814694e29be0000000001000000000093dd7400000000a86c52d501000000000093dd7400000000a8ed323228000000000093dd74eecdab8967452301174120446966666572656e74204465736372697074696f6e00".toCharArray()) ;
        byte[] digest2 = sha256.digest(data);

        String sig = "KkKmcPCFEPzodA73Un87Fb9MZ494MHH4BsmciRccC2Bue8ynvMVkcxD5PbAaRTmfCexouGJAiQkqZWAH9RCYR4tfUg2rux" ;
        String pubKey = "EOS7RCvxemGXsQHmo9JZZXNvjbKY2PL5WZV98Vt9xSNy6q68eB9k1" ;

        String recoveredKey3 = EOSKeysUtil.recoverPublicKey(sig, digest) ;
        System.out.println ( "Expected Key 3 : " + pubKey);
        System.out.println ( "Recovered Key3 : " + recoveredKey3);
    }
}
