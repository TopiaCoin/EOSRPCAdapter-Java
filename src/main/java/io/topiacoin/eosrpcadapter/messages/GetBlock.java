package io.topiacoin.eosrpcadapter.messages;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.Arrays;
import java.util.List;

public class GetBlock {
    public static class Request {
        public String block_num_or_id;
    }

    public static class Response {
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
        public List<Transaction> transactions;
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
            return "Response{" +
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
                    ", block_extenstions=" + block_extensions +
                    ", regions='" + regions + '\'' +
                    ", input_transactions='" + input_transactions + '\'' +
                    ", id='" + id + '\'' +
                    ", block_num=" + block_num +
                    ", ref_block_prefix=" + ref_block_prefix +
                    '}';
        }
    }
}
