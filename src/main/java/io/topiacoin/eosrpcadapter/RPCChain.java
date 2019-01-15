package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.exceptions.ChainException;
import io.topiacoin.eosrpcadapter.exceptions.EOSException;
import io.topiacoin.eosrpcadapter.messages.Abi;
import io.topiacoin.eosrpcadapter.messages.AccountInfo;
import io.topiacoin.eosrpcadapter.messages.Action;
import io.topiacoin.eosrpcadapter.messages.BlockInfo;
import io.topiacoin.eosrpcadapter.messages.ChainInfo;
import io.topiacoin.eosrpcadapter.messages.Code;
import io.topiacoin.eosrpcadapter.messages.ErrorResponse;
import io.topiacoin.eosrpcadapter.messages.ProducerSchedule;
import io.topiacoin.eosrpcadapter.messages.RequiredKeys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.TableRows;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import io.topiacoin.eosrpcadapter.messages.TransactionBinArgs;
import io.topiacoin.eosrpcadapter.messages.TransactionJSONArgs;
import io.topiacoin.eosrpcadapter.model.ProducerInfo;
import io.topiacoin.eosrpcadapter.util.EOSByteWriter;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.io.InputStream;
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
import java.util.Set;
import java.util.TimeZone;

public class RPCChain implements Chain {

    private final Log _log = LogFactory.getLog(this.getClass());

    private final EOSRPCAdapter rpcAdapter;
    private final URL chainURL;
    private final ObjectMapper _objectMapper;

    RPCChain(URL chainURL, EOSRPCAdapter rpcAdapter) {
        this.chainURL = chainURL;
        this.rpcAdapter = rpcAdapter;
        _objectMapper = new ObjectMapper();
        _objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @Override
    public ChainInfo getInfo() throws ChainException {
        ChainInfo getInfoResponse = null;

        try {
            URL getInfoURL = new URL(chainURL, "/v1/chain/get_info");

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.getRequest(getInfoURL);

            _log.debug("Get Info Response: " + response);

            if (response.response != null) {
                getInfoResponse = _objectMapper.readValue(response.response, ChainInfo.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new ChainException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new ChainException(e, null);
        } catch (IOException e) {
            throw new ChainException(e, null);
        } catch (EOSException e) {
            throw new ChainException(e, null);
        }

        return getInfoResponse;
    }

    @Override
    public BlockInfo getBlock(String blockNumOrID) throws ChainException {
        BlockInfo getBlockResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_block");

            Map<String, String> requestMap = new HashMap<String, String>();
            requestMap.put("block_num_or_id", blockNumOrID);

            String requestString = _objectMapper.writeValueAsString(requestMap);

            _log.debug("Get Block Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            _log.debug("Get Block Response: " + response);

            if (response.response != null) {
                getBlockResponse = _objectMapper.readValue(response.response, BlockInfo.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new ChainException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new ChainException(e, null);
        } catch (IOException e) {
            throw new ChainException(e, null);
        } catch (EOSException e) {
            throw new ChainException(e, null);
        }

        return getBlockResponse;
    }

    @Override
    public AccountInfo getAccount(String accountName) throws ChainException {
        AccountInfo getAccountResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_account");

            Map<String, String> requestMap = new HashMap<String, String>();
            requestMap.put("account_name", accountName);

            String requestString = _objectMapper.writeValueAsString(requestMap);

            _log.debug("Get Account Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            _log.debug("Get Account Response: " + response);

            if (response.response != null) {
                getAccountResponse = _objectMapper.readValue(response.response, AccountInfo.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new ChainException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new ChainException(e, null);
        } catch (IOException e) {
            throw new ChainException(e, null);
        } catch (EOSException e) {
            throw new ChainException(e, null);
        }

        return getAccountResponse;
    }

    @Override
    public ProducerSchedule getProducers() throws ChainException {
        ProducerSchedule getAccountResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_producer_schedule");

            Map<String, String> requestMap = new HashMap<String, String>();
            requestMap.put("limit", "100");

            String requestString = _objectMapper.writeValueAsString(requestMap);

            _log.debug("Get Producer Schedule Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            _log.debug("Get Producer Schedule Response: " + response);

            if (response.response != null) {
                getAccountResponse = _objectMapper.readValue(response.response, ProducerSchedule.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new ChainException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new ChainException(e, null);
        } catch (IOException e) {
            throw new ChainException(e, null);
        } catch (EOSException e) {
            throw new ChainException(e, null);
        }

        return getAccountResponse;
    }

    @Override
    public Transaction createCreateAccountTransaction(String creator, String accountName, String ownerKey, String activeKey) throws ChainException {
        List<Map<String, Object>> ownerKeysList = new ArrayList();
        Map<String, Object> ownerkeys = new HashMap<String, Object>();
        ownerkeys.put("key", ownerKey);
        ownerkeys.put("weight", 1);
        ownerKeysList.add(ownerkeys);

        List<Map<String, Object>> activeKeysList = new ArrayList();
        Map<String, Object> activekeys = new HashMap<String, Object>();
        activekeys.put("key", activeKey);
        activekeys.put("weight", 1);
        activeKeysList.add(activekeys);

        Map<String, Object> owner_authority = new HashMap<String, Object>();
        owner_authority.put("threshold", 1);
        owner_authority.put("keys", ownerKeysList);
        owner_authority.put("accounts", new ArrayList());
        owner_authority.put("waits", new ArrayList());
        Map<String, Object> active_authority = new HashMap<String, Object>();
        active_authority.put("threshold", 1);
        active_authority.put("keys", activeKeysList);
        active_authority.put("accounts", new ArrayList());
        active_authority.put("waits", new ArrayList());

        Map<String, Object> args = new HashMap<String, Object>();
        args.put("creator", creator);
        args.put("name", accountName);
        args.put("owner", owner_authority);
        args.put("active", active_authority);
        List<String> scopes = new ArrayList<String>();
        scopes.add("active");
        List<Transaction.Authorization> authorizations = new ArrayList<Transaction.Authorization>();
        authorizations.add(new Transaction.Authorization(creator, "active"));
        Date expirationDate = new Date(System.currentTimeMillis() + 60000) ;
        return createRawTransaction("eosio", "newaccount", args, scopes, authorizations, expirationDate);
    }

    @Override
    public Transaction createSetProducersTransaction(String creator, Set<ProducerInfo> producers) throws ChainException {
        if(producers.isEmpty()) {
            throw new IllegalStateException("Must provide at least one producer");
        }
        List<Map<String, Object>> producersList = new ArrayList<>();

        for(ProducerInfo producer : producers) {
            Map<String, Object> producerMap = new HashMap<>();
            producerMap.put("producer_name", producer.getProducerName());
            producerMap.put("block_signing_key", producer.getBlockSigningKey());
            producersList.add(producerMap);
        }

        Map<String, Object> args = new HashMap<>();
        args.put("schedule", producersList);

        List<String> scopes = new ArrayList<String>();
        scopes.add("active");
        List<Transaction.Authorization> authorizations = new ArrayList<Transaction.Authorization>();
        authorizations.add(new Transaction.Authorization(creator, "active"));
        Date expirationDate = new Date(System.currentTimeMillis() + 60000) ;
        return createRawTransaction("eosio", "setprods", args, scopes, authorizations, expirationDate);
    }

    @Override
    public Code getCode(String accountName) throws ChainException {
        Code getCodeResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_code");

            Map<String, String> requestMap = new HashMap<String, String>();
            requestMap.put("account_name", accountName);

            String requestString = _objectMapper.writeValueAsString(requestMap);

            _log.debug("Get Code Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            _log.debug("Get Code Response: " + response);

            if (response.response != null) {
                getCodeResponse = _objectMapper.readValue(response.response, Code.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new ChainException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new ChainException(e, null);
        } catch (IOException e) {
            throw new ChainException(e, null);
        } catch (EOSException e) {
            throw new ChainException(e, null);
        }

        return getCodeResponse;
    }

    @Override
    public TableRows getTableRows(String contract,
                                  String scope,
                                  String table,
                                  long limit,
                                  boolean reverse) throws ChainException {
        return getTableRows(contract, scope, table, 1, null, "0", "-1", limit, reverse);
    }

    @Override
    public TableRows getTableRows(String contract,
                                  String scope,
                                  String table,
                                  String lowerBound,
                                  String upperBound,
                                  long limit,
                                  boolean reverse) throws ChainException {
        return getTableRows(contract, scope, table, 1, null, lowerBound, upperBound, limit, reverse);
    }

    @Override
    public TableRows getTableRows(String contract,
                                  String scope,
                                  String table,
                                  Integer indexPosition,
                                  String keyType,
                                  String lowerBound,
                                  String upperBound,
                                  long limit,
                                  boolean reverse) throws ChainException {
        TableRows getTableRowsResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_table_rows");

            Map<String, Object> requestMap = new HashMap<String, Object>();
            requestMap.put("code", contract);
            requestMap.put("scope", scope);
            requestMap.put("table", table);
            requestMap.put("limit", limit);
            if ( indexPosition != null ) {
                requestMap.put("index_position", indexPosition);
                if ( indexPosition > 1 && keyType == null ) {
                    throw new IllegalArgumentException("Must specify keyType when using non-primary index");
                }
                if ( keyType != null ) {
                    requestMap.put("key_type", keyType);
                }
            }
            requestMap.put("lower_bound", lowerBound);
            requestMap.put("upper_bound", upperBound);
            requestMap.put("json", true);
            requestMap.put("reverse", reverse);

            String requestString = _objectMapper.writeValueAsString(requestMap);

            _log.debug("requestString: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            _log.debug("response: " + response);

            if (response.response != null) {
                getTableRowsResponse = _objectMapper.readValue(response.response, TableRows.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new ChainException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new ChainException(e, null);
        } catch (IOException e) {
            throw new ChainException(e, null);
        } catch (EOSException e) {
            throw new ChainException(e, null);
        }

        return getTableRowsResponse;
    }

    @Override
    public TransactionBinArgs abiJsonToBin(String code,
                                           String action,
                                           Map args) throws ChainException {
        TransactionBinArgs abiJsonToBinResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/abi_json_to_bin");

            Map<String, Object> requestMap = new HashMap<String, Object>();
            requestMap.put("code", code);
            requestMap.put("action", action);
            requestMap.put("args", args);

            String requestString = _objectMapper.writeValueAsString(requestMap);

            _log.debug("ABI JSON to Bin Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            _log.debug("ABI JSON to Bin Response: " + response);

            if (response.response != null) {
                abiJsonToBinResponse = _objectMapper.readValue(response.response, TransactionBinArgs.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new ChainException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new ChainException(e, null);
        } catch (IOException e) {
            throw new ChainException(e, null);
        } catch (EOSException e) {
            throw new ChainException(e, null);
        }

        return abiJsonToBinResponse;
    }

    @Override
    public TransactionJSONArgs abiBinToJson(String code,
                                            String action,
                                            String binArgs) throws ChainException {
        TransactionJSONArgs abiBinToJsonResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/abi_bin_to_json");

            Map<String, Object> requestMap = new HashMap<String, Object>();
            requestMap.put("code", code);
            requestMap.put("action", action);
            requestMap.put("binargs", binArgs);

            String requestString = _objectMapper.writeValueAsString(requestMap);

            _log.debug("ABI Bin to JSON Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            _log.debug("ABI Bin to JSON Response: " + response);

            if (response.response != null) {
                abiBinToJsonResponse = _objectMapper.readValue(response.response, TransactionJSONArgs.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new ChainException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new ChainException(e, null);
        } catch (IOException e) {
            throw new ChainException(e, null);
        } catch (EOSException e) {
            throw new ChainException(e, null);
        }

        return abiBinToJsonResponse;
    }

    @Override
    public RequiredKeys getRequiredKeys(Transaction transaction,
                                        List<String> availableKeys) throws ChainException {
        RequiredKeys getTableRowsResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_required_keys");

            Map<String, Object> requestMap = new HashMap<String, Object>();
            requestMap.put("transaction", transaction);
            requestMap.put("available_keys", new ArrayList<String>(availableKeys));

            String requestString = _objectMapper.writeValueAsString(requestMap);

            _log.debug("Get Required Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            _log.debug("Get Required Response: " + response);

            if (response.response != null) {
                getTableRowsResponse = _objectMapper.readValue(response.response, RequiredKeys.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new ChainException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new ChainException(e, null);
        } catch (IOException e) {
            throw new ChainException(e, null);
        } catch (EOSException e) {
            throw new ChainException(e, null);
        }

        return getTableRowsResponse;
    }

    @Override
    public Transaction.Response pushTransaction(SignedTransaction transaction) throws ChainException {
        Transaction.Response transactionResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/push_transaction");

            String packedTrx = packTransaction(transaction);

            Map<String, Object> pushTrx = new LinkedHashMap<String, Object>();
            pushTrx.put("signatures", transaction.signatures);
            pushTrx.put("compression", "none");
            pushTrx.put("packed_context_free_data", "");
            pushTrx.put("packed_trx", packedTrx);

            String requestString = _objectMapper.writeValueAsString(pushTrx);

            _log.debug("Push TX Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            _log.debug("Push TX Response: " + response);

            if (response.response != null) {
                transactionResponse = _objectMapper.readValue(response.response, Transaction.Response.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new ChainException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new ChainException(e, null);
        } catch (IOException e) {
            throw new ChainException(e, null);
        } catch (EOSException e) {
            throw new ChainException(e, null);
        }

        return transactionResponse;
    }

    @Override
    public List<Transaction.Response> pushTransactions(List<SignedTransaction> signedTransactions) throws ChainException {
        List<Transaction.Response> transactionResponse = null;

        try {
            List<Map<String, Object>> pushTrxs = new ArrayList<Map<String, Object>>();

            URL getBlockURL = new URL(chainURL, "/v1/chain/push_transactions");

            for (SignedTransaction transaction : signedTransactions) {
                String packedTrx = packTransaction(transaction);

                Map<String, Object> pushTrx = new LinkedHashMap<String, Object>();
                pushTrx.put("signatures", transaction.signatures);
                pushTrx.put("compression", "none");
                pushTrx.put("packed_context_free_data", "");
                pushTrx.put("packed_trx", packedTrx);

                pushTrxs.add(pushTrx);
            }

            String requestString = _objectMapper.writeValueAsString(pushTrxs);


            _log.debug("Push TXs Request: " + requestString);

            EOSRPCAdapter.EOSRPCResponse response = rpcAdapter.postRequest(getBlockURL, requestString);

            _log.debug("Push TXs Response: " + response);

            if (response.response != null) {
                transactionResponse = _objectMapper.readValue(response.response, List.class);
            } else {
                ErrorResponse errorResponse = _objectMapper.readValue(response.error.getEntity().getContent(), ErrorResponse.class);
                throw new ChainException(errorResponse.message, errorResponse);
            }
        } catch (MalformedURLException e) {
            throw new ChainException(e, null);
        } catch (IOException e) {
            throw new ChainException(e, null);
        } catch (EOSException e) {
            throw new ChainException(e, null);
        }

        return transactionResponse;
    }

    @Override
    public Transaction createRawTransaction(String account,
                                            String name,
                                            Map args,
                                            List<String> scopes,
                                            List<Transaction.Authorization> authorizations,
                                            Date expirationDate)
            throws ChainException {

        return createRawTransaction(
                new Action(account, name, authorizations, args),
                expirationDate);
    }

    @Override
    public Transaction createRawTransaction(Action action, Date expirationDate)
            throws ChainException {
        List<Action> actions = new ArrayList<>();
        actions.add(action);

        return createRawTransaction(actions, expirationDate);
    }

    @Override
    public Transaction createRawTransaction(List<Action> actions, Date expirationDate)
            throws ChainException {

        if ( actions.size() == 0 ) {
            throw new IllegalArgumentException("Must specify at least one action to include in the transaction");
        }

        TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        df.setTimeZone(tz);
        String expDateString = df.format(expirationDate);

        ChainInfo info = getInfo();
        long last_irreversible_block_num = info.last_irreversible_block_num;
        BlockInfo blockInfo = getBlock(Long.toString(last_irreversible_block_num));
        long last_irreversible_block_prefix = blockInfo.ref_block_prefix;

        ArrayList<Transaction.Action> txActions = new ArrayList<Transaction.Action>();

        for ( Action action : actions ) {
            TransactionBinArgs binArgsResponse = abiJsonToBin(
                    action.account,
                    action.name,
                    action.args);
            String binArgs = binArgsResponse.binargs;

            Transaction.Action txAction = new Transaction.Action(
                    action.account,
                    action.name,
                    action.authorizations,
                    binArgs);

            txActions.add(txAction);
        }

        Transaction transaction = new Transaction(
                expDateString,
                last_irreversible_block_num,
                last_irreversible_block_prefix,
                0,
                0,
                0,
                null,
                txActions,
                null,
                null,
                null);

        return transaction;
    }

    @Override
    public Transaction createSetContractTransaction(String account, InputStream abiStream, InputStream wasm) throws ChainException {
        byte[] abiDat;
        byte[] wasmDat;
        try {
            abiDat = IOUtils.toByteArray(abiStream);
        } catch (IOException e) {
            throw new RuntimeException("ABI data invalid", e);
        }
        try {
            wasmDat = IOUtils.toByteArray(wasm);
        } catch (IOException e) {
            throw new RuntimeException("WASM data invalid", e);
        }

        Map<String, Object> args = new HashMap<String, Object>();
        args.put("account", account);
        args.put("vmtype", 0);
        args.put("vmversion", 0);
        args.put("code", Hex.encodeHexString(wasmDat));
        List<String> scopes = new ArrayList<String>();
        scopes.add("active");
        List<Transaction.Authorization> authorizations = new ArrayList<Transaction.Authorization>();
        authorizations.add(new Transaction.Authorization(account, "active"));
        Date expirationDate = new Date(System.currentTimeMillis() + 60000) ;
        Transaction toReturn = createRawTransaction("eosio", "setcode", args, scopes, authorizations, expirationDate);

        ObjectMapper mapper = new ObjectMapper();
        Abi abi;
        try {
            abi = mapper.readValue(new String(abiDat), Abi.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read ABI", e);
        }
        EOSByteWriter setAbiWriter = new EOSByteWriter(abiDat.length);
        abi.pack(setAbiWriter);
        abiDat = setAbiWriter.toBytes();

        Map<String, Object> abiArgs = new HashMap<String, Object>();
        abiArgs.put("account", account);
        abiArgs.put("abi", Hex.encodeHexString(abiDat));
        Transaction setCodeTransaction = createRawTransaction("eosio", "setabi", abiArgs, scopes, authorizations, expirationDate);
        toReturn.actions.add(setCodeTransaction.actions.get(0));
        return toReturn;
    }


    // -------- Private Methods --------

    @Override
    public String packTransaction(SignedTransaction transaction) throws ChainException {
        String packedTrx = null;
        try {
            EOSByteWriter writer = new EOSByteWriter(4096);

            transaction.pack(writer);

            // Convert to Hex String
            byte[] bytes = writer.toBytes();
            packedTrx = Hex.encodeHexString(bytes);

        } catch (ParseException e) {
            throw new ChainException(e, null);
        }
        return packedTrx;
    }


    // -------- Accessor Methods --------


    public URL getChainURL() {
        return chainURL;
    }
}
