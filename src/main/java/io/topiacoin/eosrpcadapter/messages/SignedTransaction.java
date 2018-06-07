package io.topiacoin.eosrpcadapter.messages;

import java.util.List;

public class SignedTransaction {
    /*
  {
    "signatures": [
      "EOSKZ4pTehVfqs92wujRp34qRAvUjKJrUyufZfJDo9fdBLzhieyfUSUJpKz1Z12rxh1gTQZ4BcWvKourzxCLb2fMsvN898KSn"
    ],
    "compression": "none",
    "transaction": {
      "context_free_actions": [],
      "delay_sec": 0,
      "expiration": "2018-09-25T06:28:49",
      "max_cpu_usage_ms": 0,
      "net_usage_words": 0,
      "ref_block_num": 32697,
      "ref_block_prefix": 32649123,
      "transaction_extensions": []
      "actions": [
        {
          "account": "eosio",
          "name": "transfer",
          "authorization": [
            {
              "actor": "eosio",
              "permission": "active"
            }
          ],
          "data": "0000000050a430550000000000003ab60a000000000000000045434f0000000000"
        }
      ]
    }
  }
     */

    public List<String> signatures;
    public String compression = "none";
    public Transaction transaction;
}
