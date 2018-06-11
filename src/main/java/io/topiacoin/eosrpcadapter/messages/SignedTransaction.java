package io.topiacoin.eosrpcadapter.messages;

import io.topiacoin.eosrpcadapter.util.Base32;
import io.topiacoin.eosrpcadapter.util.EOSByteWriter;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
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
    public int max_net_usage_words;
    public int max_cpu_usage_ms;
    public int delay_sec;
    public List<String> context_free_actions;
    public List<SignedAction> actions;
    public List<String> signatures;
    public List<String> transaction_extensions;
    public List<String> context_free_data;

    public void pack(EOSByteWriter writer) throws ParseException {
        // Pack the Transaction Header
        DateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        Date expirationDate = sdf.parse(expiration);
        int expSecs = (int) (expirationDate.getTime() / 1000 + 30);
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
        for (SignedAction action : actions) {
            action.pack(writer);
        }

        // Pack the Transaction Extensions
        writer.putVariableUInt(0);

    }

    public static class SignedAction {
        public String account;
        public String name;
        public List<Transaction.Authorization> authorization;
        public String data;

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
}
