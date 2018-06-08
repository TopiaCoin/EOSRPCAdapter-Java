package io.topiacoin.eosrpcadapter.messages;

import java.util.List;

public class ListWallets {

    public static class Request {

    }

    public static class Response {
        public List<String> wallets;
    }
}
