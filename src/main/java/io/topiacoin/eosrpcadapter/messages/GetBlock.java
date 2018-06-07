package io.topiacoin.eosrpcadapter.messages;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.Arrays;
import java.util.List;

public class GetBlock {
    public static class Request {
        public String block_num_or_id;
    }

    public static class Response {
        public String previous;
        public String timestamp;
        public String transaction_mroot;
        public String action_mroot;
        public String block_mroot;
        public String producer;
        public long schedule_version;
        public List<String> new_producers;
        public String producer_signature;

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
                    "previous='" + previous + '\'' +
                    ", timestamp='" + timestamp + '\'' +
                    ", transaction_mroot='" + transaction_mroot + '\'' +
                    ", action_mroot='" + action_mroot + '\'' +
                    ", block_mroot='" + block_mroot + '\'' +
                    ", producer='" + producer + '\'' +
                    ", schedule_version=" + schedule_version +
                    ", new_producers=" + new_producers.toString() +
                    ", producer_signature='" + producer_signature + '\'' +
                    ", regions='" + regions + '\'' +
                    ", input_transactions='" + input_transactions + '\'' +
                    ", id='" + id + '\'' +
                    ", block_num=" + block_num +
                    ", ref_block_prefix=" + ref_block_prefix +
                    '}';
        }
    }
}
