package io.topiacoin.eosrpcadapter.messages;

import java.util.List;
import java.util.Map;

public class ErrorResponse {

    public int code;
    public String message;
    public Error error;

    public static class Error {
        public int code;
        public String name;
        public String what;
        public List<Map<String, Object>> details;

        @Override
        public String toString() {
            return "Error{" +
                    "code=" + code +
                    ", name='" + name + '\'' +
                    ", what='" + what + '\'' +
                    ", details=" + details +
                    '}';
        }
    }

    @Override
    public String toString() {
        return "ErrorResponse{" +
                "code=" + code +
                ", message='" + message + '\'' +
                ", error=" + error +
                '}';
    }
}



//{"code":3010002,"name":"account_query_exception","message":"Account Query Exception","stack":[{"context":{"level":"error","file":"chain_plugin.cpp","line":296,"method":"get_abi","hostname":"","thread_name":"thread-0","timestamp":"2018-05-08T21:51:31.493"},"format":"Fail to retrieve account for ${account}","data":{"account":"initb"}}]}
