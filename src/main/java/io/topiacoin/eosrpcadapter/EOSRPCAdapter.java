package io.topiacoin.eosrpcadapter;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
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

    public EOSRPCAdapter(URL nodeURL, URL walletURL) {
        this.eosNodeURL = nodeURL;
        this.eosWalletURL = walletURL;
    }

    public synchronized Wallet wallet() {
        if ( _wallet == null ){
            _wallet = new Wallet(eosWalletURL, this) ;
        }
        return _wallet;
    }

    public synchronized Chain chain() {
        if ( _chain == null ) {
            _chain = new Chain(eosNodeURL, this);
        }
        return _chain;
    }

    public synchronized AccountHistory accountHistory() {
        if ( _accountHistory == null ) {
            _accountHistory = new AccountHistory(eosNodeURL, this);
        }
        return _accountHistory;
    }

    // -------- Package Scoped methods for raw communication with the RPC API --------

    // Send a Get Request to the Server and Return the response
    EOSRPCResponse getRequest (URL url ) {
        try {
            HttpClient client = HttpClients.createDefault();

            URI getURI = url.toURI();
            HttpGet getRequest = new HttpGet(getURI);

            HttpResponse response = client.execute(getRequest);

            return validateResponse(response);
        } catch ( URISyntaxException e) {
            _log.warn ( "Exception Executing GET Request", e) ;
        } catch (ClientProtocolException e) {
            _log.warn ( "Exception Executing GET Request", e) ;
        } catch (IOException e) {
            _log.warn ( "Exception Executing GET Request", e) ;
        }

        return null;
    }

    // Send a Post Request to the Server and Return the response
    EOSRPCResponse postRequest (URL url, String rawData) {
        return postRequest(url, rawData, false);
    }

    // Send a Post Request to the Server, quoting the rawData, and Return the response
    EOSRPCResponse postRequest ( URL url, String rawData, boolean escapeQuotes) {
        try {
            String requestData = rawData;
            if ( escapeQuotes ) {
                requestData = StringEscapeUtils.escapeJavaScript(rawData);
            }

            HttpClient client = HttpClients.createDefault();

            URI getURI = url.toURI();
            HttpPost postRequest = new HttpPost(getURI);
            postRequest.setEntity(new StringEntity(requestData));

            HttpResponse response = client.execute(postRequest);

            return validateResponse(response);
        } catch ( URISyntaxException e) {
            _log.warn ( "Exception Executing GET Request", e) ;
        } catch (ClientProtocolException e) {
            _log.warn ( "Exception Executing GET Request", e) ;
        } catch (IOException e) {
            _log.warn ( "Exception Executing GET Request", e) ;
        }

        return null;
    }

    EOSRPCResponse validateResponse(HttpResponse response) throws IOException {
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
