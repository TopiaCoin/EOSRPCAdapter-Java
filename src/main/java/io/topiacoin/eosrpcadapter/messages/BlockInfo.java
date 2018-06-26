package io.topiacoin.eosrpcadapter.messages;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.List;

public class BlockInfo {
    public String timestamp;
    public String producer;
    public long confirmed;
    public String previous;
    public String transaction_mroot;
    public String action_mroot;
    public long schedule_version;
    public List<String> new_producers;
    public List<String> header_extensions;
    public String producer_signature;
    public List<BlockTransaction> transactions;
    public List<String> block_extensions;

    @JsonIgnore
    public String regions;

    @JsonIgnore
    public String input_transactions;
    public String id;
    public long block_num;
    public long ref_block_prefix;

    @Override
    public String toString() {
        return "BlockInfo{" +
                "timestamp='" + timestamp + '\'' +
                ", producer='" + producer + '\'' +
                ", confirmed=" + confirmed +
                ", previous='" + previous + '\'' +
                ", transaction_mroot='" + transaction_mroot + '\'' +
                ", action_mroot='" + action_mroot + '\'' +
                ", schedule_version=" + schedule_version +
                ", new_producers=" + new_producers +
                ", header_extensions=" + header_extensions +
                ", producer_signature='" + producer_signature + '\'' +
                ", transactions=" + transactions +
                ", block_extensions=" + block_extensions +
                ", regions='" + regions + '\'' +
                ", input_transactions='" + input_transactions + '\'' +
                ", id='" + id + '\'' +
                ", block_num=" + block_num +
                ", ref_block_prefix=" + ref_block_prefix +
                '}';
    }

    public static class BlockTransaction extends Transaction {
        public String status;
        public long cpu_usage_us;
        public long net_usage_words;
        public TransactionInfo trx;
    }

    public static class TransactionInfo {
        public String id;
        public List<String> signatures;
        public String compression;
        public String packed_context_free_data;
        public List<String> context_free_data;
        public String packed_trx;
        public Transaction transaction;
    }
}
