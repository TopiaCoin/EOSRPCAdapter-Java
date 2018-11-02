package io.topiacoin.eosrpcadapter;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.topiacoin.eosrpcadapter.exceptions.ChainException;
import io.topiacoin.eosrpcadapter.exceptions.EOSException;
import io.topiacoin.eosrpcadapter.messages.AccountInfo;
import io.topiacoin.eosrpcadapter.messages.BlockInfo;
import io.topiacoin.eosrpcadapter.messages.ChainInfo;
import io.topiacoin.eosrpcadapter.messages.Code;
import io.topiacoin.eosrpcadapter.messages.ErrorResponse;
import io.topiacoin.eosrpcadapter.messages.RequiredKeys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.TableRows;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import io.topiacoin.eosrpcadapter.messages.TransactionBinArgs;
import io.topiacoin.eosrpcadapter.messages.TransactionJSONArgs;
import io.topiacoin.eosrpcadapter.util.Base32;
import io.topiacoin.eosrpcadapter.util.Base58;
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
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
                                  boolean json) throws ChainException {
        return getTableRows(contract, scope, table, null, "0", "-1", limit, json);
    }

    @Override
    public TableRows getTableRows(String contract,
                                  String scope,
                                  String table,
                                  String lowerBound,
                                  String upperBound,
                                  long limit,
                                  boolean json) throws ChainException {
        return getTableRows(contract, scope, table, null, lowerBound, upperBound, limit, json);
    }

    @Override
    public TableRows getTableRows(String contract,
                                  String scope,
                                  String table,
                                  String key,
                                  String lowerBound,
                                  String upperBound,
                                  long limit,
                                  boolean json) throws ChainException {
        TableRows getTableRowsResponse = null;

        try {
            URL getBlockURL = new URL(chainURL, "/v1/chain/get_table_rows");

            Map<String, Object> requestMap = new HashMap<String, Object>();
            requestMap.put("code", contract);
            requestMap.put("scope", scope);
            requestMap.put("table", table);
            requestMap.put("limit", limit);
            if ( key != null ) {
                requestMap.put("table_key", key);
            }
            requestMap.put("lower_bound", lowerBound);
            requestMap.put("upper_bound", upperBound);
            requestMap.put("json", json);

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

            _log.info("ABI JSON to Bin Response: " + response);

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
                                            Date expirationDate) throws ChainException {

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

        Transaction.Action txAction = new Transaction.Action(account, name, authorizations, binArgs);

        ArrayList<Transaction.Action> actions = new ArrayList<Transaction.Action>();
        actions.add(txAction);

        Transaction transaction = new Transaction(expDateString, last_irreversible_block_num, last_irreversible_block_prefix,0, 0, 0, null, actions, null, null, null);

        return transaction;
    }

    public Transaction setContract(String account, InputStream abi, InputStream wasm) throws ChainException {
        Date expirationDate = new Date(System.currentTimeMillis() + 60000);
        String eosioAccount = "eosio";
        Transaction.Authorization authorization = new Transaction.Authorization(account, "active");
        List<Transaction.Authorization> authorizations = Arrays.asList(authorization);
        /*String abiHex;
        String wasmHex;
        try {
            abiHex = Hex.encodeHexString(IOUtils.toByteArray(abi));
        } catch (IOException e) {
            throw new RuntimeException("ABI data invalid", e);
        }
        try {
            wasmHex = Hex.encodeHexString(IOUtils.toByteArray(wasm));
        } catch (IOException e) {
            throw new RuntimeException("WASM data invalid", e);
        }*/
        byte[] abiDat;
        byte[] wasmDat;
        try {
            abiDat = IOUtils.toByteArray(abi);
        } catch (IOException e) {
            throw new RuntimeException("ABI data invalid", e);
        }
        try {
            wasmDat = IOUtils.toByteArray(wasm);
        } catch (IOException e) {
            throw new RuntimeException("WASM data invalid", e);
        }


        EOSByteWriter setCodeWriter = new EOSByteWriter(wasmDat.length + 64);
        setCodeWriter.putLong(Base32.decode(account)); //acct name
        setCodeWriter.put((byte) 0); //vmtype
        setCodeWriter.put((byte) 0); //vmversion
        setCodeWriter.putVariableUInt(wasmDat.length); //dat length
        setCodeWriter.putBytes(wasmDat); //dat

        byte[] setCodeDat = setCodeWriter.toBytes();

        EOSByteWriter setAbiWriter = new EOSByteWriter(abiDat.length + 64);
        setAbiWriter.putLong(Base32.decode(account)); //acct name
        setAbiWriter.putVariableUInt(abiDat.length); //dat length
        setAbiWriter.putBytes(abiDat);

        byte[] setAbiDat = setAbiWriter.toBytes();




        /*Map<String, Object> setCodeArgs = new HashMap();
        setCodeArgs.put("account", account);
        setCodeArgs.put("vmtype", 0);
        setCodeArgs.put("vmversion", 0);
        setCodeArgs.put("code", wasmDat);
        TransactionBinArgs setCodeBinArgsResponse = abiJsonToBin(eosioAccount, "setcode", setCodeArgs);
        String setCodeArgsStr = setCodeBinArgsResponse.binargs;*/

        Transaction.Action setCodeAction = new Transaction.Action(eosioAccount, "setcode", authorizations, Hex.encodeHexString(setCodeDat));

        Map<String, Object> setAbiArgs = new HashMap();
        setAbiArgs.put("account", account);
        setAbiArgs.put("abi", /*abiDat*/Hex.encodeHexString(abiDat));
        TransactionBinArgs setAbiBinArgsResponse = abiJsonToBin(eosioAccount, "setabi", setAbiArgs);
        String setAbiArgsStr = setAbiBinArgsResponse.binargs;

        Transaction.Action setAbiAction = new Transaction.Action(eosioAccount, "setabi", authorizations, setAbiArgsStr/*Hex.encodeHexString(setAbiDat)*/);

        ArrayList<Transaction.Action> actions = new ArrayList<Transaction.Action>();
        actions.add(setCodeAction);
        actions.add(setAbiAction);

        TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        df.setTimeZone(tz);
        String expDateString = df.format(expirationDate);

        ChainInfo info = getInfo();
        long last_irreversible_block_num = info.last_irreversible_block_num;
        BlockInfo blockInfo = getBlock(Long.toString(last_irreversible_block_num));
        long last_irreversible_block_prefix = blockInfo.ref_block_prefix;

        Transaction transaction = new Transaction(expDateString, last_irreversible_block_num, last_irreversible_block_prefix,0, 0, 0, null, actions, null, null, null);

        return transaction;
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
