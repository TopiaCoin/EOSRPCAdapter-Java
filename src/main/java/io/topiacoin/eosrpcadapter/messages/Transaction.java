package io.topiacoin.eosrpcadapter.messages;

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

    public String ref_block_num;
    public String ref_block_prefix;
    public String expiration;
    public List<String> scope;
    public List<Action> actions;
    public List<String> signatures;
    public List<Authorization> authorizations;

    public static class Action {
        public String code;
        public String type;
        public String[] recipients;
        public List<Authorization> authorizations;
        public String data;
    }

    public static class Authorization {
        public String account;
        public String permission;
    }

    public static class Response {
        public String transaction_id;
    }
}
