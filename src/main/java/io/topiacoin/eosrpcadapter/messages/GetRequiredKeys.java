package io.topiacoin.eosrpcadapter.messages;

import java.util.List;

public class GetRequiredKeys {

    public static class Request {
        public Transaction transaction;
        public List<String> available_keys;
    }

    public static class Response {
        public List<String> required_keys;
    }
}
