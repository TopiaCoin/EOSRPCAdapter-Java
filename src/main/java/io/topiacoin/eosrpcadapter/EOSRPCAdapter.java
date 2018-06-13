package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.exceptions.EOSException;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class EOSRPCAdapter {

    public static class EOSRPCResponse {
        public String response ;
        public HttpResponse error;

        public EOSRPCResponse(String response) {
            this.response = response;
        }

        public EOSRPCResponse(HttpResponse error) {
            this.error = error;
        }

        @Override
        public String toString() {
            return "EOSRPCResponse{" +
                    "response='" + response + '\'' +
                    ", error=" + error +
                    '}';
        }
    }

    private Log _log = LogFactory.getLog(this.getClass());

    private URL eosNodeURL;
    private URL eosWalletURL;

    private Wallet _wallet;
    private Chain _chain;
    private AccountHistory _accountHistory;

    /**
     * Creates a new EOS RPC Adapter instance that will connect to the specified node and wallet URLs.
     *
     * @param nodeURL The URL of the EOS node to communicate with
     * @param walletURL The URL of the EOS wallet to communicate with
     */
    public EOSRPCAdapter(URL nodeURL, URL walletURL) {
        this.eosNodeURL = nodeURL;
        this.eosWalletURL = walletURL;
    }

    /**
     * Returns an instance of the Wallet class that can be used to interact with the wallet.
     *
     * @return An instance of the Wallet class
     */
    public synchronized Wallet wallet() {
        if ( _wallet == null ){
            _wallet = new Wallet(eosWalletURL, this) ;
        }
        return _wallet;
    }

    /**
     * Returns an instance of the Chain class that can be used to interact with the chain.
     *
     * @return An instance of the Chain class
     */
    public synchronized Chain chain() {
        if ( _chain == null ) {
            _chain = new Chain(eosNodeURL, this);
        }
        return _chain;
    }

    /**
     * Returns an instance of the Account History class that can be used to retrieve history for an account.
     *
     * @return An instance of the Account History class.
     */
    public synchronized AccountHistory accountHistory() {
        if ( _accountHistory == null ) {
            _accountHistory = new AccountHistory(eosNodeURL, this);
        }
        return _accountHistory;
    }

    // -------- Package Scoped methods for raw communication with the RPC API --------

    // Send a Get Request to the Server and Return the response
    EOSRPCResponse getRequest (URL url ) throws EOSException {
        try {
            HttpClient client = HttpClients.createDefault();

            URI getURI = url.toURI();
            HttpGet getRequest = new HttpGet(getURI);

            HttpResponse response = client.execute(getRequest);

            return validateResponse(response);
        } catch ( URISyntaxException e) {
            throw new EOSException("Communications Exception", e, null);
        } catch (ClientProtocolException e) {
            throw new EOSException("Communications Exception", e, null);
        } catch (IOException e) {
            throw new EOSException("Communications Exception", e, null);
        }
    }

    // Send a Post Request to the Server and Return the response
    EOSRPCResponse postRequest (URL url, String rawData) throws EOSException {
        return postRequest(url, rawData, false);
    }

    // Send a Post Request to the Server, quoting the rawData, and Return the response
    EOSRPCResponse postRequest ( URL url, String rawData, boolean escapeQuotes) throws EOSException {
        try {
            String requestData = rawData;
            if ( escapeQuotes ) {
                requestData = StringEscapeUtils.escapeJavaScript(rawData);
            }

            HttpClient client = HttpClients.createDefault();

            URI getURI = url.toURI();
            HttpPost postRequest = new HttpPost(getURI);
            postRequest.setEntity(new StringEntity(requestData, ContentType.APPLICATION_JSON));

            HttpResponse response = client.execute(postRequest);

            return validateResponse(response);
        } catch ( URISyntaxException e) {
            throw new EOSException("Communications Exception", e, null);
        } catch (ClientProtocolException e) {
            throw new EOSException("Communications Exception", e, null);
        } catch (IOException e) {
            throw new EOSException("Communications Exception", e, null);
        }
    }

    EOSRPCResponse validateResponse(HttpResponse response) throws IOException, EOSException {
        EOSRPCResponse result;
        if ( response.getStatusLine().getStatusCode() >= 200 && response.getStatusLine().getStatusCode() < 300) {
            result = new EOSRPCResponse(IOUtils.toString(response.getEntity().getContent(), "UTF-8"));
        } else {
            result = new EOSRPCResponse(response);
        }

        return result;
    }

    // -------- Accessors Methods --------

    public void setEosNodeURL(URL eosNodeURL) {
        this.eosNodeURL = eosNodeURL;
    }

    public void setEosWalletURL(URL eosWalletURL) {
        this.eosWalletURL = eosWalletURL;
    }
}
