package io.topiacoin.eosrpcadapter.messages;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class GetAccount {

    public static class Request {

        public String account_name;
    }

    public static class Response {
        public String account_name;
        public boolean privileged;
        public String last_code_update;
        public String created;
        public long ram_quota;
        public long net_weight;
        public long cpu_weight;
        public Map<String, Long> net_limit;
        public Map<String, Long> cpu_limit;
        public long ram_usage;
        public AccountPermission[] permissions;

        public String total_resources;
        public String self_delegated_bandwidth;
        public String voter_info;

        @Override
        public String toString() {
            return "Response{" +
                    "account_name='" + account_name + '\'' +
                    ", privileged=" + privileged +
                    ", last_code_update='" + last_code_update + '\'' +
                    ", created='" + created + '\'' +
                    ", ram_quota=" + ram_quota +
                    ", net_weight=" + net_weight +
                    ", cpu_weight=" + cpu_weight +
                    ", net_limit=" + net_limit +
                    ", cpu_limit=" + cpu_limit +
                    ", ram_usage=" + ram_usage +
                    ", permissions=" + Arrays.toString(permissions) +
                    ", total_resources='" + total_resources + '\'' +
                    ", self_delegated_bandwidth='" + self_delegated_bandwidth + '\'' +
                    ", voter_info='" + voter_info + '\'' +
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
        public String[] waits;

        @Override
        public String toString() {
            return "RequiredAuth{" +
                    "threshold=" + threshold +
                    ", keys=" + Arrays.toString(keys) +
                    ", accounts=" + Arrays.toString(accounts) +
                    ", waits=" + Arrays.toString(waits) +
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