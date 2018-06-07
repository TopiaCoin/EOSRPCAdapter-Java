package io.topiacoin.eosrpcadapter.messages;

import java.util.Arrays;
import java.util.List;

public class GetAccount {

    public static class Request {

        public String account_name;
    }

    public static class Response {
        public String account_name;
        public AccountPermission[] permissions;

        public String name;
        public String eos_balance;
        public String staked_balance;
        public String unstaked_balance;
        public String last_unstaking_time;

        @Override
        public String toString() {
            return "Response{" +
                    "account_name='" + account_name + '\'' +
                    ", permissions=" + Arrays.toString(permissions) +
                    ", name='" + name + '\'' +
                    ", eos_balance='" + eos_balance + '\'' +
                    ", staked_balance='" + staked_balance + '\'' +
                    ", unstaked_balance='" + unstaked_balance + '\'' +
                    ", last_unstaking_time='" + last_unstaking_time + '\'' +
                    '}';
        }
    }

    public static class AccountPermission {
        public String perm_name;
        public String parent;
        public RequiredAuth required_auth;

        @Override
        public String toString() {
            return "AccountPermission{" +
                    "perm_name='" + perm_name + '\'' +
                    ", parent='" + parent + '\'' +
                    ", required_auth=" + required_auth +
                    '}';
        }
    }

    public static class RequiredAuth {
        public int threshold;
        public KeyWeights[] keys;
        public String[] accounts;

        @Override
        public String toString() {
            return "RequiredAuth{" +
                    "threshold=" + threshold +
                    ", keys=" + Arrays.toString(keys) +
                    ", accounts=" + Arrays.toString(accounts) +
                    '}';
        }
    }

    public static class KeyWeights {
        public String key;
        public int weight;

        @Override
        public String toString() {
            return "KeyWeights{" +
                    "key='" + key + '\'' +
                    ", weight=" + weight +
                    '}';
        }
    }
}


/*
{"account_name":"inita","permissions":[{"perm_name":"active","parent":"owner","required_auth":{"threshold":1,"keys":[{"key":"EOS6js37ofHj5Tf3DsGiSuwjA1BrkyuhMaoChhwtGhKdRRGUuXBvu","weight":1}],"accounts":[]}},{"perm_name":"owner","parent":"","required_auth":{"threshold":1,"keys":[{"key":"EOS6js37ofHj5Tf3DsGiSuwjA1BrkyuhMaoChhwtGhKdRRGUuXBvu","weight":1}],"accounts":[]}}]}[admins-imac:~] john%

 */