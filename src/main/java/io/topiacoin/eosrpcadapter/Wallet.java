package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.messages.CreateKey;
import io.topiacoin.eosrpcadapter.messages.CreateWallet;
import io.topiacoin.eosrpcadapter.messages.ImportKey;
import io.topiacoin.eosrpcadapter.messages.ListKeys;
import io.topiacoin.eosrpcadapter.messages.ListWallets;
import io.topiacoin.eosrpcadapter.messages.LockWallet;
import io.topiacoin.eosrpcadapter.messages.OpenWallet;
import io.topiacoin.eosrpcadapter.messages.ListPublicKeys;
import io.topiacoin.eosrpcadapter.messages.SetTimeout;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import io.topiacoin.eosrpcadapter.messages.UnlockWallet;
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

    public CreateKey.Response createKey() {

        EOSKey eosKey = EOSKey.randomKey();
        CreateKey.Response response = new CreateKey.Response();
        response.eosKey = eosKey.toWif();

        return response ;
    }

    public ListWallets.Response list() {
        ListWallets.Response getInfoResponse = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/list_wallets");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.getRequest(getInfoURL);

            System.out.println("response: " + response);

            ObjectMapper om = new ObjectMapper();
            getInfoResponse = new ListWallets.Response();
            List<String> wallets = om.readValue(response.response, List.class);
            getInfoResponse.wallets = wallets;
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (JsonParseException e) {
            e.printStackTrace();
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return getInfoResponse;
    }

    public OpenWallet.Response open(String name) {
        OpenWallet.Response openInfoResponse = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/open");

            String walletName = "\"" + name + "\"";

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, walletName);

            System.out.println("response: " + response);

            ObjectMapper om = new ObjectMapper();
            openInfoResponse =  om.readValue(response.response, OpenWallet.Response.class);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (JsonParseException e) {
            e.printStackTrace();
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return openInfoResponse;
    }

    public CreateWallet.Response create(String name) {
        CreateWallet.Response openInfoResponse = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/create");

            String walletName = "\"" + name + "\"";

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, walletName);

            System.out.println("response: " + response);

            openInfoResponse = new CreateWallet.Response();
            openInfoResponse.password = response.response.replaceAll("\"", "") ;
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return openInfoResponse;
    }

    public LockWallet.Response lock(String name) {
        LockWallet.Response openInfoResponse = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/lock");

            String walletName = "\"" + name + "\"";

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, walletName);

            System.out.println("response: " + response);

            openInfoResponse = new LockWallet.Response();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return openInfoResponse;
    }

    public UnlockWallet.Response unlock(String name, String password) {
        UnlockWallet.Response openInfoResponse = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/unlock");

            String request = "[\"" + name + "\",\"" + password + "\"]" ;

            System.out.println("Unlock Request: " + request);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, request);

            System.out.println("Unlock Response: " + response);

            if ( response.response != null ) {
                openInfoResponse = new UnlockWallet.Response();
            }else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8") ;
                System.out.println ( "Error Message: " + errorMessage);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return openInfoResponse;
    }

    public LockWallet.Response lockAll() {
        LockWallet.Response openInfoResponse = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/lock_all");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, "");

            System.out.println("response: " + response);

            openInfoResponse = new LockWallet.Response();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return openInfoResponse;
    }

    public ListPublicKeys.Response getPublicKeys() {
        ListPublicKeys.Response openInfoResponse = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/get_public_keys");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.getRequest(getInfoURL);

            System.out.println("Get Public Response: " + response);

            if ( response.response != null ) {
                ObjectMapper om = new ObjectMapper();
                List<String> publicKeys = om.readValue(response.response, List.class);
                openInfoResponse = new ListPublicKeys.Response();
                openInfoResponse.publicKeys = publicKeys;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return openInfoResponse;
    }

    public ListKeys.Response listKeys() {
        ListKeys.Response openInfoResponse = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/list_keys");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.getRequest(getInfoURL);

            System.out.println("response: " + response);

            ObjectMapper om = new ObjectMapper();
            List<List<String>> keys = om.readValue(response.response, List.class);
            openInfoResponse = new ListKeys.Response();
            openInfoResponse.keys = keys ;
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return openInfoResponse;
    }

    public ImportKey.Response importKey(String name, String key) {
        ImportKey.Response openInfoResponse = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/import_key");

            String request = "[\"" + name + "\",\"" + key + "\"]" ;

            System.out.println("Import Request: " + request);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, request);

            System.out.println("response: " + response);

            if ( response.response != null ) {
                openInfoResponse = new ImportKey.Response();
            }else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8") ;
                System.out.println ( "Error Message: " + errorMessage);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return openInfoResponse;
    }

    public SetTimeout.Response setTimeout(int timeoutSecs) {
        SetTimeout.Response setTimeoutResponse = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/set_timeout");

            String request = "" + timeoutSecs ;

            System.out.println("Import Request: " + request);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, request);

            System.out.println("response: " + response);

            if ( response.response != null ) {
                setTimeoutResponse = new SetTimeout.Response();
            }else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8") ;
                System.out.println ( "Error Message: " + errorMessage);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return setTimeoutResponse;
    }

    public SignedTransaction signTransaction (Transaction transaction, String[] keys) {
        return signTransaction(transaction, keys, "");
    }

    public SignedTransaction signTransaction (Transaction transaction, String[] keys, String chainID) {
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
