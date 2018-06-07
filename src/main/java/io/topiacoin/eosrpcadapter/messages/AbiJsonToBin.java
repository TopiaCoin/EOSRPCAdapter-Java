package io.topiacoin.eosrpcadapter.messages;

import com.fasterxml.jackson.annotation.JsonRawValue;

import java.util.List;
import java.util.Map;

public class AbiJsonToBin {

    public static class Request {
        public String code;
        public String action;
//        @JsonRawValue
        public Map args;
    }

    public static class Response {
        public String binargs;
        public List<String> required_scope;
        public List<String> required_auth;
    }
}
