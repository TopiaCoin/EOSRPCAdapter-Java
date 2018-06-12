package io.topiacoin.eosrpcadapter.messages;

import io.topiacoin.eosrpcadapter.util.Base32;
import io.topiacoin.eosrpcadapter.util.EOSByteWriter;
import org.bouncycastle.util.encoders.Hex;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

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
      "authorization": []
    }
     */

    public String expiration;
    public long ref_block_num;
    public long ref_block_prefix;
    public int max_net_usage_words;
    public int max_cpu_usage_ms;
    public int delay_sec;
    public List<String> context_free_actions = new ArrayList<String>();
    public List<Action> actions = new ArrayList<Action>();
    public List<String> transaction_extensions = new ArrayList<String>();
    public List<String> signatures = new ArrayList<String>();
    public List<String> context_free_data = new ArrayList<String>();

    public void pack(EOSByteWriter writer) throws ParseException {
        // Pack the Transaction Header
        TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        sdf.setTimeZone(tz);
        Date expirationDate = sdf.parse(expiration);
        int expSecs = (int) (expirationDate.getTime() / 1000);
        writer.putInt(expSecs);
        writer.putShort((short) (ref_block_num & 0xFFFF));
        writer.putInt((int) (ref_block_prefix & 0xFFFFFFFF));
        writer.putVariableUInt(max_net_usage_words);
        writer.putVariableUInt(max_cpu_usage_ms);
        writer.putVariableUInt(delay_sec);

        // Pack the Context Free Actions
        writer.putVariableUInt(0);

        // Pack the Actions
        writer.putVariableUInt(actions.size());
        for (Transaction.Action action : actions) {
            action.pack(writer);
        }

        // Pack the Transaction Extensions
        writer.putVariableUInt(0);

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


    public static class Action {
        public String account;
        public String name;
        public List<Authorization> authorization;
        public String data;

        @Override
        public String toString() {
            return "Action{" +
                    "account='" + account + '\'' +
                    ", name='" + name + '\'' +
                    ", authorization=" + authorization +
                    ", data='" + data + '\'' +
                    '}';
        }

        public void pack(EOSByteWriter writer) {
            // Base32 decode the account and name to long's.
            long accountLong = Base32.decode(account);
            long nameLong = Base32.decode(name);

            writer.putLong(accountLong);
            writer.putLong(nameLong);

            // Serialize the Authorizations
            writer.putVariableUInt(authorization.size());
            for (Transaction.Authorization auth : authorization) {
                auth.pack(writer);
            }

            byte[] decodedData = Hex.decode(data);
            writer.putVariableUInt(decodedData.length);
            writer.putBytes(decodedData);
        }

    }

    public static class Authorization {
        public String actor;
        public String permission;

        public void pack(EOSByteWriter writer) {
            // Base32 decode the account and permission to long's.
            long accountLong = Base32.decode(actor);
            long permLong = Base32.decode(permission);

            writer.putLong(accountLong);
            writer.putLong(permLong);
        }

        @Override
        public String toString() {
            return "Authorization{" +
                    "actor='" + actor + '\'' +
                    ", permission='" + permission + '\'' +
                    '}';
        }
    }

    public static class Response {
        public String transaction_id;
        public Map<String, Object> processed;

        @Override
        public String toString() {
            return "Response{" +
                    "transaction_id='" + transaction_id + '\'' +
                    ", processed=" + processed +
                    '}';
        }
    }

}
