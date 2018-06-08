package io.topiacoin.eosrpcadapter.messages;

import java.util.List;

public class SignedTransaction {
    /*
{
  "expiration": "2018-06-08T20:24:56",
  "region": 0,
  "ref_block_num": 60464,
  "ref_block_prefix": 3714577127,
  "max_net_usage_words": 0,
  "max_kcpu_usage": 0,
  "delay_sec": 0,
  "context_free_actions": [],
  "actions": [
    {
      "account": "",
      "name": "",
      "authorization": [],
      "data": "000000000093dd740000000000ea305589674523010000000000000000000000"
    }
  ],
  "signatures": [
    "EOSK9y3ZoryNoxyRCmz1EfLwx5W6wgzL66HQCbMHqm119FfYvDUmuF1xJjns7LkjdPVVnd9AkSoeJYjP56pJqarkP5fQ3rhPH",
    "EOSK1kRu2ws3CpK7xbqKvdHttfx2G9vsciaN6T2yEBuwRW8V4CXuL1LAzNhHuE3r2QTazwCtGe2KCP1qcz1SFAtBGo3QhA3Q6",
    "EOSKZgmaPN3rQhdEBmRoQoZ4rnm4hW4tvZ8q4WREP3Lam9wMwaKWG8PB3FHFnMYTrWMj7STa5sZP6jnes8bnG36pBs8WrzXGt"
  ],
  "context_free_data": []
}     */

    public String expiration;
    public long region;
    public long ref_block_num;
    public long ref_block_prefix;
    public long max_net_usage_words;
    public long max_kcpu_usage;
    public long delay_sec;
    public List<String> context_free_actions;
    public List<SignedAction> actions;
    public List<String> signatures;
    public List<String> context_free_data;


    public static class SignedAction {
        public String account;
        public String name;
        public List<Transaction.Authorization> authorization;
        public String data;
    }
}
