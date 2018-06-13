package io.topiacoin.eosrpcadapter.messages;

import java.util.ArrayList;
import java.util.List;

public class SignedTransaction extends Transaction {

    public SignedTransaction() {
        context_free_actions = new ArrayList<String>();
        actions = new ArrayList<Transaction.Action>();
        signatures = new ArrayList<String>();
        transaction_extensions = new ArrayList<String>();
        context_free_data = new ArrayList<String>();
    }

    public SignedTransaction(Transaction trx, List<String> signatures){
        this.expiration = trx.expiration;
        this.ref_block_num = trx.ref_block_num;
        this.ref_block_prefix = trx.ref_block_prefix;
        this.max_cpu_usage_ms = trx.max_cpu_usage_ms;
        this.max_net_usage_words = trx.max_net_usage_words;
        this.context_free_actions = new ArrayList<String>(trx.context_free_actions);
        this.actions = new ArrayList<Transaction.Action>(trx.actions);
        this.signatures = new ArrayList<String>(signatures);
        this.transaction_extensions = new ArrayList<String>(trx.transaction_extensions);
        this.context_free_data = new ArrayList<String>(trx.context_free_data);
    }
}
