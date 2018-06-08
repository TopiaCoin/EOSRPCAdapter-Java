package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.messages.AbiBinToJson;
import io.topiacoin.eosrpcadapter.messages.AbiJsonToBin;
import io.topiacoin.eosrpcadapter.messages.GetAccount;
import io.topiacoin.eosrpcadapter.messages.GetBlock;
import io.topiacoin.eosrpcadapter.messages.GetCode;
import io.topiacoin.eosrpcadapter.messages.GetInfo;
import io.topiacoin.eosrpcadapter.messages.GetRequiredKeys;
import io.topiacoin.eosrpcadapter.messages.GetTableRows;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

public class Chain {

    private final EOSRPCAdapter rpcAdapter;
    private final URL chainURL;

    Chain(URL chainURL, EOSRPCAdapter rpcAdapter) {
        this.chainURL = chainURL;
        this.rpcAdapter = rpcAdapter;
    }

    public GetInfo.Response getInfo() {
        GetInfo.Response getInfoResponse = null;

        try {
            URL getInfoURL = new URL(chainURL, "/v1/chain/get_info");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.getRequest(getInfoURL);

            System.out.println("response: " + response);

            ObjectMapper om = new ObjectMapper();
            getInfoResponse = om.readValue(response.response, GetInfo.Response.class);
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

    public GetBlock.Response getBlock(String blockNumOrID) {
        GetBlock.Response getBlockResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_block");

            GetBlock.Request request = new GetBlock.Request();
            request.block_num_or_id = blockNumOrID;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(request);

            System.out.println("requestString: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("response: " + response);

            if (response.response != null) {
                getBlockResponse = om.readValue(response.response, GetBlock.Response.class);
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

        return getBlockResponse;
    }

    public GetAccount.Response getAccount(String accountName) {
        GetAccount.Response getAccountRespons = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_account");

            GetAccount.Request request = new GetAccount.Request();
            request.account_name = accountName;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(request);

            System.out.println("requestString: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("response: " + response);

            if (response.response != null) {
                getAccountRespons = om.readValue(response.response, GetAccount.Response.class);
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

        return getAccountRespons;
    }

    public GetCode.Response getCode(String accountName) {
        GetCode.Response getCodeResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_code");

            GetCode.Request request = new GetCode.Request();
            request.account_name = accountName;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(request);

            System.out.println("requestString: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("response: " + response);

            if (response.response != null) {
                getCodeResponse = om.readValue(response.response, GetCode.Response.class);
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

        return getCodeResponse;
    }

    public GetTableRows.Response getTableRows(String contract, String scope, String table, boolean json) {
        GetTableRows.Response getTableRowsResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_table_rows");

            GetTableRows.Request request = new GetTableRows.Request();
            request.code = contract;
            request.scope = scope;
            request.table = table;
            request.json = json;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(request);

            System.out.println("requestString: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("response: " + response);

            if (response.response != null) {
                getTableRowsResponse = om.readValue(response.response, GetTableRows.Response.class);
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

        return getTableRowsResponse;
    }

    public AbiJsonToBin.Response abiJsonToBin(String code, String action, Map args) {
        AbiJsonToBin.Response abiJsonToBinResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/abi_json_to_bin");

            AbiJsonToBin.Request request = new AbiJsonToBin.Request();
            request.code = code;
            request.action = action;
            request.args = args;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(request);

            System.out.println("requestString: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("response: " + response);

            if (response.response != null) {
                abiJsonToBinResponse = om.readValue(response.response, AbiJsonToBin.Response.class);
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

        return abiJsonToBinResponse;
    }

    public AbiBinToJson.Response abiBinToJson(String code, String action, String binArgs) {
        AbiBinToJson.Response abiBinToJsonResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/abi_bin_to_json");

            AbiBinToJson.Request request = new AbiBinToJson.Request();
            request.code = code;
            request.action = action;
            request.binargs = binArgs;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(request);

            System.out.println("requestString: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("response: " + response);

            if (response.response != null) {
                abiBinToJsonResponse = om.readValue(response.response, AbiBinToJson.Response.class);
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

        return abiBinToJsonResponse;
    }

    public Transaction.Response pushTransaction(SignedTransaction transaction) {
        Transaction.Response transactionResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/push_transaction");

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(transaction);

            System.out.println("requestString: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("response: " + response);

            if (response.response != null) {
                transactionResponse = om.readValue(response.response, Transaction.Response.class);
            } else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8") ;
                System.out.println ( "Error Message: " + errorMessage);
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

        return transactionResponse;
    }

    public void pushTransactions(Transaction[] signedTransactions) {

    }

    public GetRequiredKeys.Response getRequiredKeys(Transaction transaction, String[] availableKeys) {
        GetRequiredKeys.Response getTableRowsResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_required_keys");

            GetRequiredKeys.Request request = new GetRequiredKeys.Request();
            request.transaction = transaction ;
            request.available_keys = Arrays.asList(availableKeys) ;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(request);

            System.out.println("requestString: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("response: " + response);

            if (response.response != null) {
                getTableRowsResponse = om.readValue(response.response, GetRequiredKeys.Response.class);
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

        return getTableRowsResponse;
    }

    public Transaction createRawTransaction(String code, String action, Map args, List<String> scopes, List<Transaction.Authorization> authorizations, Date expirationDate) {

        TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        df.setTimeZone(tz);
        String expDateString = df.format(expirationDate) ;

        AbiJsonToBin.Response binArgsResponse = abiJsonToBin(code, action, args);
        String binArgs = binArgsResponse.binargs;

        Transaction.Action txAction = new Transaction.Action();
        txAction.code = code;
        txAction.type = action;
        txAction.data = binArgs;
        txAction.authorizations = authorizations;
        txAction.recipients = new String[]{code};

        Transaction transaction = new Transaction();
        transaction.ref_block_num = "126000";
        transaction.ref_block_prefix = "3714577127";
        transaction.actions = new ArrayList<Transaction.Action>();
        transaction.actions.add(txAction);
        transaction.scope = scopes;
        transaction.authorizations = new ArrayList<Transaction.Authorization>();
        transaction.signatures = new ArrayList<String>();
        transaction.expiration = expDateString;

        return transaction;
    }


    // -------- Accessor Methods --------


    public URL getChainURL() {
        return chainURL;
    }
}
