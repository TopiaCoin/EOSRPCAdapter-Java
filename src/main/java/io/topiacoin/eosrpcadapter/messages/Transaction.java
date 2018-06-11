package io.topiacoin.eosrpcadapter.messages;

import io.topiacoin.eosrpcadapter.Base58;
import io.topiacoin.eosrpcadapter.util.Base32;
import io.topiacoin.eosrpcadapter.util.EOSByteWriter;

import java.math.BigInteger;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class Transaction {
    /*
    {
      "ref_block_num": "100",
      "ref_block_prefix": "137469861",
      "expiration": "2017-09-25T06:28:49",
      "scope": [
        "initb",
        "initc"
      ],
      "actions": [
        {
          "code": "currency",
          "type": "transfer",
          "recipients": [
            "initb",
            "initc"
          ],
          "authorization": [
            {
              "account": "initb",
              "permission": "active"
            }
          ],
          "data": "000000000041934b000000008041934be803000000000000"
        }
      ],
      "signatures": [],
      "authorizations": []
    }
     */

    public String expiration;
    public String ref_block_num;
    public String ref_block_prefix;
    public int max_net_usage_words;
    public int max_cpu_usage_ms;
    public int delay_sec;
    public List<String> context_free_actions = new ArrayList<String>();
    public List<Action> actions = new ArrayList<Action>();
    public List<String> transaction_extensions = new ArrayList<String>();
    public List<String> signatures = new ArrayList<String>();
    public List<String> context_free_data = new ArrayList<String>();

    public static class Action {
        public String code;
        public String type;
        public String[] recipients;
        public List<Authorization> authorizations;
        public String data;

        @Override
        public String toString() {
            return "Action{" +
                    "code='" + code + '\'' +
                    ", type='" + type + '\'' +
                    ", recipients=" + Arrays.toString(recipients) +
                    ", authorizations=" + authorizations +
                    ", data='" + data + '\'' +
                    '}';
        }
    }

    public static class Authorization {
        public String account;
        public String permission;

        public void pack(EOSByteWriter writer) {
            // Base32 decode the account and permission to long's.
            long accountLong = Base32.decode(account);
            long permLong = Base32.decode(permission);

            writer.putLong(accountLong);
            writer.putLong(permLong);
        }

        @Override
        public String toString() {
            return "Authorization{" +
                    "account='" + account + '\'' +
                    ", permission='" + permission + '\'' +
                    '}';
        }
    }

    public static class Response {
        public String transaction_id;
    }

    @Override
    public String toString() {
        return "Transaction{" +
                "expiration='" + expiration + '\'' +
                ", ref_block_num='" + ref_block_num + '\'' +
                ", ref_block_prefix='" + ref_block_prefix + '\'' +
                ", max_net_usage_words=" + max_net_usage_words +
                ", max_cpu_usage_ms=" + max_cpu_usage_ms +
                ", delay_sec=" + delay_sec +
                ", context_free_actions=" + context_free_actions +
                ", actions=" + actions +
                ", transaction_extensions=" + transaction_extensions +
                ", signatures=" + signatures +
                ", context_free_data=" + context_free_data +
                '}';
    }
}
