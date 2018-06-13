package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.messages.ErrorResponse;
import io.topiacoin.eosrpcadapter.messages.Keys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class Wallet {

    private final EOSRPCAdapter rpcAdapter;
    private final URL walletURL ;

    Wallet(URL walletURL, EOSRPCAdapter rpcAdapter) {
        this.walletURL = walletURL;
        this.rpcAdapter = rpcAdapter;
    }

    public String createKey() {

        EOSKey eosKey = EOSKey.randomKey();

        return eosKey.toWif() ;
    }

    public List<String> list() {
        List<String> walletList = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/list_wallets");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.getRequest(getInfoURL);

            System.out.println("response: " + response);

            if (response.response != null ) {
                ObjectMapper om = new ObjectMapper();
                walletList = om.readValue(response.response, List.class);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (JsonParseException e) {
            e.printStackTrace();
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return walletList;
    }

    public boolean open(String name) {
        boolean opened = false ;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/open");

            String walletName = "\"" + name + "\"";

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, walletName);

            System.out.println("response: " + response);

            opened = response.response != null ;

        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        return opened;
    }

    public String create(String name) {
        String password = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/create");

            String walletName = "\"" + name + "\"";

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, walletName);

            System.out.println("response: " + response);

            if ( response.response != null ) {
                password = response.response.replaceAll("\"", "");
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        return password;
    }

    public boolean lock(String name) {
        boolean locked = false ;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/lock");

            String walletName = "\"" + name + "\"";

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, walletName);

            System.out.println("response: " + response);

            locked = response.response != null;
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        return locked;
    }

    public boolean unlock(String name, String password) {
        boolean unlocked = false ;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/unlock");

            String request = "[\"" + name + "\",\"" + password + "\"]" ;

            System.out.println("Unlock Request: " + request);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, request);

            System.out.println("Unlock Response: " + response);

            if ( response.response != null ) {
                unlocked = true ;
            }else {

                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8") ;
                ObjectMapper om = new ObjectMapper();
                ErrorResponse errorResponse = om.readValue(errorMessage, ErrorResponse.class);
                System.out.println ( "Error Response: " + errorResponse);

                // 3120007 - The wallet is already unlocked, so just ignore the error
                unlocked = ( errorResponse.error.code == 3120007 ) ;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return unlocked;
    }

    public boolean lockAll() {
        boolean locked = false ;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/lock_all");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, "");

            System.out.println("response: " + response);

            locked = (response.response != null );
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        return locked;
    }

    public List<String> getPublicKeys() {
        List<String> publicKeys = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/get_public_keys");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.getRequest(getInfoURL);

            System.out.println("Get Public Response: " + response);

            if ( response.response != null ) {
                ObjectMapper om = new ObjectMapper();
                publicKeys = om.readValue(response.response, List.class);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return publicKeys;
    }

    public Keys listKeys(String name, String password) {
        Keys keys = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/list_keys");

            String request = "[\"" + name + "\",\"" + password + "\"]" ;

            System.out.println("List Keys Request: " + request);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, request);

            System.out.println("List Keys Response: " + response);

            if ( response.response != null ) {
                ObjectMapper om = new ObjectMapper();
                List<List<String>> listOfKeyPairs = om.readValue(response.response, List.class);
                keys = new Keys();
                keys.keys = new ArrayList<Keys.KeyPair>();
                for ( List<String> curKeyPair : listOfKeyPairs ) {
                    Keys.KeyPair keyPair = new Keys.KeyPair(curKeyPair.get(0), curKeyPair.get(1));
                    keys.keys.add(keyPair);
                }
            } else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8") ;
                System.out.println ( "Error Message: " + errorMessage);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return keys;
    }

    public boolean importKey(String name, String key) {
        boolean imported = false ;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/import_key");

            String request = "[\"" + name + "\",\"" + key + "\"]" ;

            System.out.println("Import Request: " + request);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, request);

            System.out.println("response: " + response);

            if ( response.response != null ) {
                imported = true ;
            }else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8") ;
                System.out.println ( "Error Message: " + errorMessage);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return imported;
    }

    public boolean setTimeout(int timeoutSecs) {
        boolean timeoutSet = false ;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/set_timeout");

            String request = "" + timeoutSecs ;

            System.out.println("Import Request: " + request);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, request);

            System.out.println("response: " + response);

            if ( response.response != null ) {
                timeoutSet = true ;
            }else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8") ;
                System.out.println ( "Error Message: " + errorMessage);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return timeoutSet;
    }

    public SignedTransaction signTransaction (Transaction transaction, List<String> keys) {
        return signTransaction(transaction, keys, "");
    }

    public SignedTransaction signTransaction (Transaction transaction, List<String> keys, String chainID) {
        SignedTransaction signedTransaction = null ;

        try {
            ObjectMapper om = new ObjectMapper();
            om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

            URL getInfoURL = new URL(walletURL, "/v1/wallet/sign_transaction");

            List<Object> request = new ArrayList<Object>();
            request.add(transaction);
            request.add(keys);
            request.add(chainID);

            String requestString = om.writeValueAsString(request);

            System.out.println("Sign Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, requestString);

            System.out.println("Sign Response: " + response);

            if ( response.response != null ) {
                signedTransaction = om.readValue(response.response, SignedTransaction.class);
                List<String> signatures = signedTransaction.signatures;
                signedTransaction = new SignedTransaction(transaction, signatures);
            }else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8") ;
                System.out.println ( "Error Message: " + errorMessage);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return signedTransaction;
    }

    // -------- Accessor Methods --------


    public URL getWalletURL() {
        return walletURL;
    }
}
