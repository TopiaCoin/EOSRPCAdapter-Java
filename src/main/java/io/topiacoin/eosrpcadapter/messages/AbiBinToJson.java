package io.topiacoin.eosrpcadapter.messages;

import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Map;

public class AbiBinToJson {

    public static class Request {

        public String code;
        public String action;
        public String binargs;
        public boolean json = true;

        public int limit = 500;
    }

    public static class Response {
        public Map args;
        public List<String> required_scope;
        public List<String> required_auth;
    }
}
