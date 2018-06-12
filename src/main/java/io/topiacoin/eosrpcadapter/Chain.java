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
import java.util.Arrays;
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

    public GetInfo.Response getInfo() {
        GetInfo.Response getInfoResponse = null;

        try {
            URL getInfoURL = new URL(chainURL, "/v1/chain/get_info");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.getRequest(getInfoURL);

            System.out.println("Get Info Response: " + response);

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

            System.out.println("Get Block Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("Get Block Response: " + response);

            if (response.response != null) {
                getBlockResponse = om.readValue(response.response, GetBlock.Response.class);
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

    public GetAccount.Response getAccount(String accountName) {
        GetAccount.Response getAccountResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_account");

            GetAccount.Request request = new GetAccount.Request();
            request.account_name = accountName;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(request);

            System.out.println("Get Account Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("Get Account Response: " + response);

            if (response.response != null) {
                getAccountResponse = om.readValue(response.response, GetAccount.Response.class);
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

    public GetCode.Response getCode(String accountName) {
        GetCode.Response getCodeResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_code");

            GetCode.Request request = new GetCode.Request();
            request.account_name = accountName;

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(request);

            System.out.println("Get Code Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("Get Code Response: " + response);

            if (response.response != null) {
                getCodeResponse = om.readValue(response.response, GetCode.Response.class);
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

            System.out.println("ABI JSON to Bin Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("ABI JSON to Bin Response: " + response);

            if (response.response != null) {
                abiJsonToBinResponse = om.readValue(response.response, AbiJsonToBin.Response.class);
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

            System.out.println("ABI Bin to JSON Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("ABI Bin to JSON Response: " + response);

            if (response.response != null) {
                abiBinToJsonResponse = om.readValue(response.response, AbiBinToJson.Response.class);
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

    public GetRequiredKeys.Response getRequiredKeys(Transaction transaction, List<String> availableKeys) {
        GetRequiredKeys.Response getTableRowsResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_required_keys");

            GetRequiredKeys.Request request = new GetRequiredKeys.Request();
            request.transaction = transaction;
            request.available_keys = new ArrayList<String>(availableKeys);

            ObjectMapper om = new ObjectMapper();
            String requestString = om.writeValueAsString(request);

            System.out.println("Get Required Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            System.out.println("Get Required Response: " + response);

            if (response.response != null) {
                getTableRowsResponse = om.readValue(response.response, GetRequiredKeys.Response.class);
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

    public Transaction createRawTransaction(String account, String name, Map args, List<String> scopes, List<Transaction.Authorization> authorizations, Date expirationDate) {

        TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        df.setTimeZone(tz);
        String expDateString = df.format(expirationDate);

        GetInfo.Response info = getInfo();
        long last_irreversible_block_num = info.last_irreversible_block_num;
        GetBlock.Response blockInfo = getBlock(Long.toString(last_irreversible_block_num));
        long last_irreversible_block_prefix = blockInfo.ref_block_prefix;

        AbiJsonToBin.Response binArgsResponse = abiJsonToBin(account, name, args);
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


    /*
        TransactionHeader::serialize(writer);

        SerializeCollection(context_free_action, writer);
        SerializeCollection(actions, writer);
        SerializeCollection(transaction_extensions, writer);
    */
    /*
        void TransactionHeader::serialize(EOSByteWriter *writer) const
        {
           if (writer) {
               QDateTime date = QDateTime::fromString(QString::fromStdString(expiration), Qt::ISODate);
               writer->putIntLE((int)(date.toMSecsSinceEpoch() / 1000 + date.offsetFromUtc() + EXPIRATION_SEC));
               writer->putShortLE((short)ref_block_num & 0xFFFF);
               writer->putIntLE((int)(ref_block_prefix & 0xFFFFFFFF));
               writer->putVariableUInt(net_usage_words);
               writer->putVariableUInt(kcpu_usage);
               writer->putVariableUInt(delay_seconds);
           }
        }
    */
    /*
        template<typename T>
        void SerializeCollection(const std::vector<T>& list, EOSByteWriter *writer)
        {
            if (writer) {
                writer->putVariableUInt(list.size());
                for (auto item : list) {
                    item.serialize(writer);
                }
            }
        }

     */
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
