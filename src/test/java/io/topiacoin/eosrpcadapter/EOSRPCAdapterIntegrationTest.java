package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.exceptions.EOSException;
import io.topiacoin.eosrpcadapter.messages.RequiredKeys;
import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.TableRows;
import io.topiacoin.eosrpcadapter.messages.Transaction;
import org.junit.Ignore;
import org.junit.Test;

import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.Assert.*;

@Ignore
public class EOSRPCAdapterIntegrationTest {

    @Test
    public void testIntegration() throws Exception {

        URL nodeURL = new URL("http://127.0.0.1:8888/");
        URL walletURL = new URL ("http://127.0.0.1:8899/");

        String accountName = "inita";
        String walletName = "default";
        String walletPassword = "PW5KhNWRhmkmSV718ivUgvtDdsG5Rd291MrJm6PJESeDVpo5AQ7gV" ;

        long guid = new Random().nextLong();
        String workspaceName = "workspace-" + guid;
        String workspaceDescription = "Description! " + guid ;

        EOSRPCAdapter eosrpcAdapter = new EOSRPCAdapter(nodeURL, walletURL);

        Chain chain = eosrpcAdapter.chain();
        Wallet wallet = eosrpcAdapter.wallet();

        String chainID = chain.getInfo().chain_id;

        // Unlock the Wallet
        wallet.unlock(walletName, walletPassword) ;
        List<String> availableKeys = wallet.getPublicKeys(walletName);

        // Load the Smart Contract into the inita account
        try
        {
            InputStream abiStream = ClassLoader.getSystemResourceAsStream("contract.abi");
            InputStream wasmStream = ClassLoader.getSystemResourceAsStream("contract.wasm");
            Transaction smartContractTx = chain.createSetContractTransaction(accountName, abiStream, wasmStream);

            RequiredKeys requiredKeys = chain.getRequiredKeys(smartContractTx, availableKeys);

            SignedTransaction signedContractTx = wallet.signTransaction(smartContractTx, requiredKeys.required_keys, chainID);

            chain.pushTransaction(signedContractTx);
        } catch ( EOSException e ){
            System.out.println ( "Exception loading Contract: " + e.getMessage());
        }

        // Invoke the Smart Contract to Create the Workspace
        {
            Map args = new HashMap();
            args.put("owner", accountName);
            args.put("guid", guid);
            args.put("workspaceName", workspaceName);
            args.put("workspaceDescription", workspaceDescription);
            args.put("key", "sekretKey");
            List<String> scope = new ArrayList<>();
            List<Transaction.Authorization> authorizations = new ArrayList<>();
            authorizations.add(new Transaction.Authorization(accountName, "active"));
            Date expirationDate = new Date(System.currentTimeMillis() + 60000);
            Transaction createContainerTx = chain.createRawTransaction(accountName, "create", args, scope, authorizations, expirationDate);

            RequiredKeys requiredKeys = chain.getRequiredKeys(createContainerTx, availableKeys);

            SignedTransaction signedContainerTx = wallet.signTransaction(createContainerTx, requiredKeys.required_keys, chainID);

            chain.pushTransaction(signedContainerTx);
        }

        // Read the table rows out of the contract
        {
            String guidStr = "" + guid;
            TableRows tableRows = chain.getTableRows(accountName, guidStr, "workspace", 10, false);

            System.out.println(tableRows.rows);
            Map<String, Object> row = tableRows.rows.get(0);
            assertEquals ( workspaceName, row.get("name"));
            assertEquals ( workspaceDescription, row.get("description"));
            assertEquals ( accountName, row.get("owner"));
        }

        // Invoke the Smart Contract to Delete the Workspace
        {
            Map args = new HashMap();
            args.put("guid", guid);
            List<String> scope = new ArrayList<>();
            List<Transaction.Authorization> authorizations = new ArrayList<>();
            authorizations.add(new Transaction.Authorization(accountName, "active"));
            Date expirationDate = new Date(System.currentTimeMillis() + 60000);
            Transaction createContainerTx = chain.createRawTransaction(accountName, "destroy", args, scope, authorizations, expirationDate);

            RequiredKeys requiredKeys = chain.getRequiredKeys(createContainerTx, availableKeys);

            SignedTransaction signedContainerTx = wallet.signTransaction(createContainerTx, requiredKeys.required_keys, chainID);

            chain.pushTransaction(signedContainerTx);
        }

        // Try to Read the table rows out of the contract
        {
            String guidStr = "" + guid;
            TableRows tableRows = chain.getTableRows(accountName, guidStr, "workspace", 10, false);

            System.out.println(tableRows.rows);

            assertEquals ( 0, tableRows.rows.size());
        }

    }
}
