package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.util.EOSKeysUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

public class EOSWalletSample {

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        if ( true )
        {
            String walletName = "/Users/john/eosio-wallet/default";
            String password = "PW5JJ4t4Bfg42YXUScNY6WVo7Gn8GAK6P7CJQfTPWNMqYiqRES9J1";

            // Load the Wallet
            JavaWallet.EOSWallet wallet = JavaWallet.EOSWallet.loadWallet(walletName);

            System.out.println("Loaded  : " + wallet);

            // Unlock the Wallet
            wallet.unlock(password);

            System.out.println("Unlocked: " + wallet);

            // Access the items in the Wallet
            for (List<String> keyPair: wallet.listPrivateKeys()) {

                String publicKey = keyPair.get(0);
                String privateKey = keyPair.get(1);

                // Get the Private Key from the Private Key WIF String
                ECPrivateKey ecPrivateKey = EOSKeysUtil.checkAndDecodePrivateKey(privateKey);
                System.out.println("Private Key  : " + ecPrivateKey);

                // Get the Public Key from the Public Key WIF String
                ECPublicKey ecPublicKey = EOSKeysUtil.checkAndDecodePublicKey(publicKey);
                System.out.println("From Public  : " + ecPublicKey);

                // Get the Public Key from the *Private* Key WIF String
                ecPublicKey = EOSKeysUtil.checkAndDecodePublicKeyFromPrivateKeyString(privateKey);
                System.out.println("From Private : " + ecPublicKey);
            }

            // Lock the Wallet
            wallet.lock();

            System.out.println("Locked  : " + wallet);

            // Save the Wallet
            wallet.saveWallet();

            // Create a brand new wallet
            String newPassword = EOSKeysUtil.generateRandomPassword();
            wallet = JavaWallet.EOSWallet.createWallet("sample", newPassword);

            System.out.println("New      : " + wallet);

            // Create a Key in the Wallet
            String publicKey = wallet.createKey();

            System.out.println("With Key : " + wallet);

            // Import a Key into the Wallet
            String newPubKey = null; // EOS8agBfR3DABrBc8Pj38nyby41QW3xPJWGHmvfP9dzde9ZfsqZhb
            String newPrivKey = "5HzsKHxUK6s75jv66j5MNNLkLrWQt6Ng4MYWhbmfKwqUHk4sNgy";
            newPubKey = wallet.importKey(newPrivKey);

            System.out.println("Import   : " + wallet);

            // Load and Unlock the new wallet
            wallet = JavaWallet.EOSWallet.loadWallet("sample");
            wallet.unlock(newPassword);

            System.out.println("UnLocked : " + wallet);

            // List the Public Keys in the Wallet
            List<String> publicKeys = wallet.listPublicKeys();

            System.out.println("Public Keys: " + publicKeys);

            // List the Private Keys in the Wallet
            List<List<String>> privateKeys = wallet.listPrivateKeys();

            System.out.println("Private Keys: " + privateKeys);

            // Remove Key from the Wallet
            wallet.removeKey(newPubKey);

            System.out.println("Removed   : " + wallet);

            // TODO - Sign with the Wallet
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            String message = "foobarbazfizzbuzz";
            byte[] digest = sha256.digest(message.getBytes());
            String signature = wallet.signDigest(digest, publicKey);

            System.out.println("Message : " + message);
            System.out.println("Signature : " + signature);

            // TODO - Verify Signature with the Wallet
            boolean verified = wallet.verifySignature(digest, signature, publicKey);

            System.out.println("Verified : " + verified);

            String recoveredKey = EOSKeysUtil.recoverPublicKey(signature, digest);

            System.out.println("Expected Key   : " + publicKey);
            System.out.println("Recovered Key  : " + recoveredKey);


//            byte[] data = Hex.decodeHex("c321495bd814694e29be0000000001000000000093dd7400000000a86c52d501000000000093dd7400000000a8ed323228000000000093dd74eecdab8967452301174120446966666572656e74204465736372697074696f6e00".toCharArray());
//            byte[] digest2 = sha256.digest(data);
//
//            String sig = "SIG_K1_K8QzgABZrxFeJUm9PY1rVdBiWRJDCEXU5zGy1CjZdkxqz3NaxUE2Vv3Adn51WMtXadihSPA6RSHWwjRAfgYe5WTafUdzn5";
//            String pubKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV";
//
//            String recoveredKey3 = EOSKeysUtil.recoverPublicKey(sig, digest2);
//            System.out.println("Expected Key 3 : " + pubKey);
//            System.out.println("Recovered Key3 : " + recoveredKey3);
        }

        {
            String pubKeyString = "EOS7RCvxemGXsQHmo9JZZXNvjbKY2PL5WZV98Vt9xSNy6q68eB9k1";
            String pubKeyString2 = "PUB_K1_7RCvxemGXsQHmo9JZZXNvjbKY2PL5WZV98Vt9xSNy6q68de18Q";

            ECPublicKey pubKey1 = EOSKeysUtil.checkAndDecodePublicKey(pubKeyString) ;
            ECPublicKey pubKey2 = EOSKeysUtil.checkAndDecodePublicKey(pubKeyString);
            ECPublicKey pubKey3 = EOSKeysUtil.checkAndDecodePublicKey(pubKeyString2);

            System.out.println ( "Pub Key 1: " + pubKey1) ;
            System.out.println ( "Pub Key 2: " + pubKey2) ;
            System.out.println ( "Pub Key 3: " + pubKey3) ;
        }

        {
            String privKeyString = "5HzsKHxUK6s75jv66j5MNNLkLrWQt6Ng4MYWhbmfKwqUHk4sNgy" ;
            String privKeyString2 = "PRV_K1_5HzsKHxUK6s75jv66j5MNNLkLrWQt6Ng4MYWhbmfKwqUHk4sNgy" ;

            ECPrivateKey privKey1 = EOSKeysUtil.checkAndDecodePrivateKey(privKeyString) ;
            ECPrivateKey privKey2 = EOSKeysUtil.checkAndDecodePrivateKey(privKeyString);
            ECPrivateKey privKey3 = EOSKeysUtil.checkAndDecodePrivateKey(privKeyString2);

            System.out.println ( "Priv Key 1: " + privKey1) ;
            System.out.println ( "Priv Key 2: " + privKey2) ;
            System.out.println ( "Priv Key 3: " + privKey3) ;

        }

        {
            String signature="EOSKkKmcPCFEPzodA73Un87Fb9MZ494MHH4BsmciRccC2Bue8ynvMVkcxD5PbAaRTmfCexouGJAiQkqZWAH9RCYR4tfUg2rux";
            String signature2 = "SIG_K1_KkKmcPCFEPzodA73Un87Fb9MZ494MHH4BsmciRccC2Bue8ynvMVkcxD5PbAaRTmfCexouGJAiQkqZWAH9RCYR4tfUg2rux";

            EOSKeysUtil.SignatureComponents signatureComponents1 = EOSKeysUtil.checkAndDecodeSignature(signature);
            EOSKeysUtil.SignatureComponents signatureComponents2 = EOSKeysUtil.checkAndDecodeSignature(signature2);

            System.out.println ( "Signature 1: " + signatureComponents1);
            System.out.println ( "Signature 2: " + signatureComponents2);
        }

        {
            String pubKeyString = "EOS7RCvxemGXsQHmo9JZZXNvjbKY2PL5WZV98Vt9xSNy6q68eB9k1";
            String pubKeyString2 = "PUB_K1_7RCvxemGXsQHmo9JZZXNvjbKY2PL5WZV98Vt9xSNy6q68de18Q";

            ECPublicKey publicKey = EOSKeysUtil.checkAndDecodePublicKey(pubKeyString) ;
            ECPublicKey publicKey2 = EOSKeysUtil.checkAndDecodePublicKey(pubKeyString2);

            String legacyToLegacyPubKeyString = EOSKeysUtil.encodeAndCheckPublicKey(publicKey, true);
            String newToNewPubKeyString = EOSKeysUtil.encodeAndCheckPublicKey(publicKey2, false);
            String legacyToNewPubKeyString = EOSKeysUtil.encodeAndCheckPublicKey(publicKey, false);
            String newToLegacyPubKeyString = EOSKeysUtil.encodeAndCheckPublicKey(publicKey2, true);

            System.out.println ( "Legacy Pub Key : " + pubKeyString);
            System.out.println ( "New Pub Key    : " + pubKeyString2);

            System.out.println ( "L2L Pub Key    : " + legacyToLegacyPubKeyString);
            System.out.println ( "N2N Pub Key    : " + newToNewPubKeyString);
            System.out.println ( "L2N Pub Key    : " + legacyToNewPubKeyString);
            System.out.println ( "N2L Pub Key    : " + newToLegacyPubKeyString);

        }

        System.out.println();

        {
            String privKeyString = "5HzsKHxUK6s75jv66j5MNNLkLrWQt6Ng4MYWhbmfKwqUHk4sNgy" ;
            String privKeyString2 = "PRV_K1_5HzsKHxUK6s75jv66j5MNNLkLrWQt6Ng4MYWhbmfKwqUHk4sNgy" ;

            ECPrivateKey privKey1 = EOSKeysUtil.checkAndDecodePrivateKey(privKeyString) ;
            ECPrivateKey privKey2 = EOSKeysUtil.checkAndDecodePrivateKey(privKeyString);

            String legacyToLegacyPrivKeyString = EOSKeysUtil.encodeAndCheckPrivateKey(privKey1, true);
            String newToNewPrivKeyString = EOSKeysUtil.encodeAndCheckPrivateKey(privKey2, false);
            String legacyToNewPrivKeyString = EOSKeysUtil.encodeAndCheckPrivateKey(privKey1, false);
            String newToLegacyPrivKeyString = EOSKeysUtil.encodeAndCheckPrivateKey(privKey2, true);

            System.out.println ( "Legacy Priv Key : " + privKeyString);
            System.out.println ( "New Priv Key    : " + privKeyString2);

            System.out.println ( "L2L Priv Key    : " + legacyToLegacyPrivKeyString);
            System.out.println ( "N2N Priv Key    : " + newToNewPrivKeyString);
            System.out.println ( "L2N Priv Key    : " + legacyToNewPrivKeyString);
            System.out.println ( "N2L Priv Key    : " + newToLegacyPrivKeyString);


        }

        System.out.println();

        {
            String signature="EOSKkKmcPCFEPzodA73Un87Fb9MZ494MHH4BsmciRccC2Bue8ynvMVkcxD5PbAaRTmfCexouGJAiQkqZWAH9RCYR4tfUg2rux";
            String signature2 = "SIG_K1_KkKmcPCFEPzodA73Un87Fb9MZ494MHH4BsmciRccC2Bue8ynvMVkcxD5PbAaRTmfCexouGJAiQkqZWAH9RCYR4tfUg2rux";

            EOSKeysUtil.SignatureComponents signatureComponents1 = EOSKeysUtil.checkAndDecodeSignature(signature);
            EOSKeysUtil.SignatureComponents signatureComponents2 = EOSKeysUtil.checkAndDecodeSignature(signature2);

            String legacyToLegacySignatureString = EOSKeysUtil.encodeAndCheckSignature(signatureComponents1.r, signatureComponents1.s, signatureComponents1.i, true);
            String newToNewSignatureString = EOSKeysUtil.encodeAndCheckSignature(signatureComponents2.r, signatureComponents2.s, signatureComponents2.i, false);
            String legacyToNewSignatureString = EOSKeysUtil.encodeAndCheckSignature(signatureComponents1.r, signatureComponents1.s, signatureComponents1.i, false);
            String newToLegacySignatureString = EOSKeysUtil.encodeAndCheckSignature(signatureComponents2.r, signatureComponents2.s, signatureComponents2.i, true);

            System.out.println ( "Signature 1: " + signatureComponents1);
            System.out.println ( "Signature 2: " + signatureComponents2);

            System.out.println ( "L2L Signature    : " + legacyToLegacySignatureString);
            System.out.println ( "N2N Signature    : " + newToNewSignatureString);
            System.out.println ( "L2N Signature    : " + legacyToNewSignatureString);
            System.out.println ( "N2L Signature    : " + newToLegacySignatureString);

        }

    }
}
