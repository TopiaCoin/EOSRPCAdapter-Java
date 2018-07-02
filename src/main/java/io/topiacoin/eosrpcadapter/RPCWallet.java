package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.exceptions.EOSException;
import io.topiacoin.eosrpcadapter.exceptions.WalletException;
import io.topiacoin.eosrpcadapter.messages.ErrorResponse;
import io.topiacoin.eosrpcadapter.messages.Keys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class RPCWallet implements Wallet {

    private final Log _log = LogFactory.getLog(this.getClass());

    private final EOSRPCAdapter rpcAdapter;
    private final URL walletURL;
    private final ObjectMapper _objectMapper;

    RPCWallet(URL walletURL, EOSRPCAdapter rpcAdapter) {
        this.walletURL = walletURL;
        this.rpcAdapter = rpcAdapter;

        _objectMapper = new ObjectMapper();
        _objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @Override
    public String createKey() throws WalletException {

        EOSKey eosKey = EOSKey.randomKey();

        return eosKey.toWif();
    }

    @Override
    public List<String> list() throws WalletException {
        List<String> walletList = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/list_wallets");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.getRequest(getInfoURL);

            _log.debug("List Wallets Response: " + response);

            if (response.response != null) {
                walletList = _objectMapper.readValue(response.response, List.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new WalletException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new WalletException(e, null);
        } catch (IOException e) {
            throw new WalletException(e, null);
        } catch (EOSException e) {
            throw new WalletException(e, null);
        }

        return walletList;
    }

    @Override
    public boolean open(String name) throws WalletException {
        boolean opened = false;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/open");

            String walletName = "\"" + name + "\"";

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, walletName);

            _log.debug("Open Wallet Response: " + response);

            if (response.response != null) {
                opened = true;
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new WalletException(errorResponse.message, errorResponse);
            }

        } catch (MalformedURLException e) {
            throw new WalletException(e, null);
        } catch (IOException e) {
            throw new WalletException(e, null);
        } catch (EOSException e) {
            throw new WalletException(e, null);
        }

        return opened;
    }

    @Override
    public String create(String name) throws WalletException {
        String password = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/create");

            String walletName = "\"" + name + "\"";

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, walletName);

            _log.debug("Create Wallet Response: " + response);

            if (response.response != null) {
                password = response.response.replaceAll("\"", "");
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new WalletException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new WalletException(e, null);
        } catch (IOException e) {
            throw new WalletException(e, null);
        } catch (EOSException e) {
            throw new WalletException(e, null);
        }

        return password;
    }

    @Override
    public boolean lock(String name) throws WalletException {
        boolean locked = false;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/lock");

            String walletName = "\"" + name + "\"";

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, walletName);

            _log.debug("Lock Wallet Response: " + response);

            if (response.response != null) {
                locked = true;
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new WalletException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new WalletException(e, null);
        } catch (IOException e) {
            throw new WalletException(e, null);
        } catch (EOSException e) {
            throw new WalletException(e, null);
        }

        return locked;
    }

    @Override
    public boolean unlock(String name,
                          String password) throws WalletException {
        boolean unlocked = false;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/unlock");

            String request = "[\"" + name + "\",\"" + password + "\"]";

            _log.debug("Unlock Request: " + request);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, request);

            _log.debug("Unlock Response: " + response);

            if (response.response != null) {
                unlocked = true;
            } else {

                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8");
                ErrorResponse errorResponse = _objectMapper.readValue(errorMessage, ErrorResponse.class);
                _log.debug("Error Response: " + errorResponse);

                // 3120007 - The wallet is already unlocked, so just ignore the error
                if (errorResponse.error.code == 3120007) {
                    unlocked = true;
                } else {
                    throw new WalletException(errorResponse.message, errorResponse);
                }
            }
        } catch (MalformedURLException e) {
            throw new WalletException(e, null);
        } catch (IOException e) {
            throw new WalletException(e, null);
        } catch (EOSException e) {
            throw new WalletException(e, null);
        }

        return unlocked;
    }

    @Override
    public boolean lockAll() throws WalletException {
        boolean locked = false;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/lock_all");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, "");

            _log.debug("Lock All Wallets Response: " + response);

            if (response.response != null) {
                locked = true;
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new WalletException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new WalletException(e, null);
        } catch (IOException e) {
            throw new WalletException(e, null);
        } catch (EOSException e) {
            throw new WalletException(e, null);
        }

        return locked;
    }

    @Override
    public List<String> getPublicKeys(String name) throws WalletException {
        List<String> publicKeys = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/get_public_keys");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.getRequest(getInfoURL);

            _log.debug("Get Public Keys Response: " + response);

            if (response.response != null) {
                publicKeys = _objectMapper.readValue(response.response, List.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new WalletException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new WalletException(e, null);
        } catch (IOException e) {
            throw new WalletException(e, null);
        } catch (EOSException e) {
            throw new WalletException(e, null);
        }

        return publicKeys;
    }

    @Override
    public Keys listKeys(String name,
                         String password) throws WalletException {
        Keys keys = null;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/list_keys");

            String request = "[\"" + name + "\",\"" + password + "\"]";

            _log.debug("List Keys Request: " + request);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, request);

            _log.debug("List Keys Response: " + response);

            if (response.response != null) {
                List<List<String>> listOfKeyPairs = _objectMapper.readValue(response.response, List.class);
                keys = new Keys();
                keys.keys = new ArrayList<Keys.KeyPair>();
                for (List<String> curKeyPair : listOfKeyPairs) {
                    Keys.KeyPair keyPair = new Keys.KeyPair(curKeyPair.get(0), curKeyPair.get(1));
                    keys.keys.add(keyPair);
                }
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new WalletException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new WalletException(e, null);
        } catch (IOException e) {
            throw new WalletException(e, null);
        } catch (EOSException e) {
            throw new WalletException(e, null);
        }

        return keys;
    }

    @Override
    public boolean importKey(String name,
                             String key) throws WalletException {
        boolean imported = false;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/import_key");

            String request = "[\"" + name + "\",\"" + key + "\"]";

            _log.debug("Import Key Request: " + request);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, request);

            _log.debug("Import Key Response: " + response);

            if (response.response != null) {
                imported = true;
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new WalletException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new WalletException(e, null);
        } catch (IOException e) {
            throw new WalletException(e, null);
        } catch (EOSException e) {
            throw new WalletException(e, null);
        }

        return imported;
    }

    @Override
    public boolean setTimeout(String name, int timeoutSecs) throws WalletException {
        boolean timeoutSet = false;

        try {
            URL getInfoURL = new URL(walletURL, "/v1/wallet/set_timeout");

            String request = "" + timeoutSecs;

            _log.debug("Set Timeout Request: " + request);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, request);

            _log.debug("Set Timeout Response: " + response);

            if (response.response != null) {
                timeoutSet = true;
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new WalletException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new WalletException(e, null);
        } catch (IOException e) {
            throw new WalletException(e, null);
        } catch (EOSException e) {
            throw new WalletException(e, null);
        }

        return timeoutSet;
    }

    @Override
    public SignedTransaction signTransaction(Transaction transaction,
                                             List<String> keys) throws WalletException {
        return signTransaction(transaction, keys, "");
    }

    @Override
    public SignedTransaction signTransaction(Transaction transaction,
                                             List<String> keys,
                                             String chainID) throws WalletException {
        SignedTransaction signedTransaction = null;

        try {

            URL getInfoURL = new URL(walletURL, "/v1/wallet/sign_transaction");

            List<Object> request = new ArrayList<Object>();
            request.add(transaction);
            request.add(keys);
            request.add(chainID);

            String requestString = _objectMapper.writeValueAsString(request);

            _log.debug("Sign Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getInfoURL, requestString);

            _log.debug("Sign Response: " + response);

            if (response.response != null) {
                signedTransaction = _objectMapper.readValue(response.response, SignedTransaction.class);
                List<String> signatures = signedTransaction.signatures;
                signedTransaction = new SignedTransaction(transaction, signatures);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new WalletException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new WalletException(e, null);
        } catch (IOException e) {
            throw new WalletException(e, null);
        } catch (EOSException e) {
            throw new WalletException(e, null);
        }

        return signedTransaction;
    }

    // -------- Accessor Methods --------


    @Override
    public URL getWalletURL() {
        return walletURL;
    }
}
