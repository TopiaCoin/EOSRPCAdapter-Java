package io.topiacoin.eosrpcadapter.messages;

import java.util.List;

public class ListKeys {
    public static class Response {

        public List<List<String>> keys;
    }
}
