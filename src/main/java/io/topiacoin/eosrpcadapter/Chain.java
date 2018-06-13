package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.messages.AccountInfo;
import io.topiacoin.eosrpcadapter.messages.BlockInfo;
import io.topiacoin.eosrpcadapter.messages.ChainInfo;
import io.topiacoin.eosrpcadapter.messages.Code;
import io.topiacoin.eosrpcadapter.messages.GetTableRows;
import io.topiacoin.eosrpcadapter.messages.RequiredKeys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import io.topiacoin.eosrpcadapter.messages.TransactionBinArgs;
import io.topiacoin.eosrpcadapter.messages.TransactionJSONArgs;
import io.topiacoin.eosrpcadapter.util.EOSByteWriter;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
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

    public ChainInfo getInfo() {
        ChainInfo getInfoResponse = null;

        try {
            URL getInfoURL = new URL(chainURL, "/v1/chain/get_info");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.getRequest(getInfoURL);

            System.out.println("Get Info Response: " + response);

            ObjectMapper om = new ObjectMapper();
            getInfoResponse = om.readValue(response.response, ChainInfo.class);
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

    public BlockInfo getBlock(String blockNumOrID) {
        BlockInfo getBlockResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_block");

            Map<String, String> requestMap = new HashMap<String, String>();
            requestMap.put("block_num_or_id", blockNumOrID) ;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(requestMap);

            System.out.println("Get Block Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("Get Block Response: " + response);

            if (response.response != null) {
                getBlockResponse = om.readValue(response.response, BlockInfo.class);
            } else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8");
                System.out.println("Error Message: " + errorMessage);
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

    public AccountInfo getAccount(String accountName) {
        AccountInfo getAccountResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_account");

            Map<String, String> requestMap = new HashMap<String, String>();
            requestMap.put("account_name", accountName) ;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(requestMap);

            System.out.println("Get Account Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("Get Account Response: " + response);

            if (response.response != null) {
                getAccountResponse = om.readValue(response.response, AccountInfo.class);
            } else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8");
                System.out.println("Error Message: " + errorMessage);
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

        return getAccountResponse;
    }

    public Code getCode(String accountName) {
        Code getCodeResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_code");

            Map<String, String> requestMap = new HashMap<String, String>();
            requestMap.put("account_name", accountName) ;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(requestMap);

            System.out.println("Get Code Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("Get Code Response: " + response);

            if (response.response != null) {
                getCodeResponse = om.readValue(response.response, Code.class);
            } else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8");
                System.out.println("Error Message: " + errorMessage);
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

            Map<String, Object> requestMap = new HashMap<String, Object>();
            requestMap.put("code", contract) ;
            requestMap.put("scope", scope) ;
            requestMap.put("table", table) ;
            requestMap.put("json", json) ;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(requestMap);

            System.out.println("requestString: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("response: " + response);

            if (response.response != null) {
                getTableRowsResponse = om.readValue(response.response, GetTableRows.Response.class);
            } else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8");
                System.out.println("Error Message: " + errorMessage);
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

    public TransactionBinArgs abiJsonToBin(String code, String action, Map args) {
        TransactionBinArgs abiJsonToBinResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/abi_json_to_bin");

            Map<String, Object> requestMap = new HashMap<String, Object>();
            requestMap.put("code", code) ;
            requestMap.put("action", action) ;
            requestMap.put("args", args) ;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(requestMap);

            System.out.println("ABI JSON to Bin Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("ABI JSON to Bin Response: " + response);

            if (response.response != null) {
                abiJsonToBinResponse = om.readValue(response.response, TransactionBinArgs.class);
            } else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8");
                System.out.println("Error Message: " + errorMessage);
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

    public TransactionJSONArgs abiBinToJson(String code, String action, String binArgs) {
        TransactionJSONArgs abiBinToJsonResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/abi_bin_to_json");

            Map<String, Object> requestMap = new HashMap<String, Object>();
            requestMap.put("code", code) ;
            requestMap.put("action", action) ;
            requestMap.put("binargs", binArgs) ;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(requestMap);

            System.out.println("ABI Bin to JSON Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("ABI Bin to JSON Response: " + response);

            if (response.response != null) {
                abiBinToJsonResponse = om.readValue(response.response, TransactionJSONArgs.class);
            } else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8");
                System.out.println("Error Message: " + errorMessage);
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

    public RequiredKeys getRequiredKeys(Transaction transaction, List<String> availableKeys) {
        RequiredKeys getTableRowsResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_required_keys");

            Map<String, Object> requestMap = new HashMap<String, Object>();
            requestMap.put("transaction", transaction) ;
            requestMap.put("available_keys", new ArrayList<String>(availableKeys)) ;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(requestMap);

            System.out.println("Get Required Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("Get Required Response: " + response);

            if (response.response != null) {
                getTableRowsResponse = om.readValue(response.response, RequiredKeys.class);
            } else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8");
                System.out.println("Error Message: " + errorMessage);
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

    public Transaction.Response pushTransaction(SignedTransaction transaction) {
        Transaction.Response transactionResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/push_transaction");

            EOSByteWriter writer = new EOSByteWriter(4096);
            transaction.pack(writer);
            String packedTrx = Hex.encodeHexString(writer.toBytes());

            Map<String, Object> pushTrx = new LinkedHashMap<String,Object>();
            pushTrx.put("signatures", transaction.signatures);
            pushTrx.put("compression", "none");
            pushTrx.put("packed_context_free_data", "");
            pushTrx.put("packed_trx", packedTrx);

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(pushTrx);

            System.out.println("Push TX Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("Push TX Response: " + response);

            if (response.response != null) {
                transactionResponse = om.readValue(response.response, Transaction.Response.class);
            } else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8");
                System.out.println("Error Message: " + errorMessage);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (JsonParseException e) {
            e.printStackTrace();
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return transactionResponse;
    }

    public List<Transaction.Response> pushTransactions(List<SignedTransaction> signedTransactions) {
        List<Transaction.Response> transactionResponse = null;

        try {
            List<Map<String, Object>> pushTrxs = new ArrayList<Map<String, Object>>();

            URL getBlockURL = new URL(chainURL, "/v1/chain/push_transactions");

            for ( SignedTransaction transaction : signedTransactions) {
                EOSByteWriter writer = new EOSByteWriter(4096);
                transaction.pack(writer);
                String packedTrx = Hex.encodeHexString(writer.toBytes());

                Map<String, Object> pushTrx = new LinkedHashMap<String, Object>();
                pushTrx.put("signatures", transaction.signatures);
                pushTrx.put("compression", "none");
                pushTrx.put("packed_context_free_data", "");
                pushTrx.put("packed_trx", packedTrx);

                pushTrxs.add(pushTrx);
            }

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(pushTrxs);


            System.out.println("Push TX Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("Push TX Response: " + response);

            if (response.response != null) {
                transactionResponse = om.readValue(response.response, List.class);
            } else {
                String errorMessage = IOUtils.toString(response.error.getEntity().getContent(), "UTF-8");
                System.out.println("Error Message: " + errorMessage);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (JsonParseException e) {
            e.printStackTrace();
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return transactionResponse;
    }

    public Transaction createRawTransaction(String account, String name, Map args, List<String> scopes, List<Transaction.Authorization> authorizations, Date expirationDate) {

        TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        df.setTimeZone(tz);
        String expDateString = df.format(expirationDate);

        ChainInfo info = getInfo();
        long last_irreversible_block_num = info.last_irreversible_block_num;
        BlockInfo blockInfo = getBlock(Long.toString(last_irreversible_block_num));
        long last_irreversible_block_prefix = blockInfo.ref_block_prefix;

        TransactionBinArgs binArgsResponse = abiJsonToBin(account, name, args);
        String binArgs = binArgsResponse.binargs;

        Transaction.Action txAction = new Transaction.Action();
        txAction.account = account;
        txAction.name = name;
        txAction.data = binArgs;
        txAction.authorization = authorizations;

        Transaction transaction = new Transaction();
        transaction.ref_block_num = last_irreversible_block_num;
        transaction.ref_block_prefix = last_irreversible_block_prefix;
        transaction.actions = new ArrayList<Transaction.Action>();
        transaction.actions.add(txAction);
        transaction.signatures = new ArrayList<String>();
        transaction.expiration = expDateString;

        return transaction;
    }

    
    // -------- Private Methods --------

    public String packTransaction(SignedTransaction transaction) {
        String packedTrx = null ;
        try {
            EOSByteWriter writer = new EOSByteWriter(4096);

            transaction.pack(writer);

            // Convert to Hex String
            byte[] bytes = writer.toBytes();
            packedTrx = Hex.encodeHexString(bytes);

        } catch (ParseException e) {
            e.printStackTrace();
        }
        return packedTrx ;
    }


    // -------- Accessor Methods --------


    public URL getChainURL() {
        return chainURL;
    }
}
