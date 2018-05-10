package io.topiacoin.eosrpcadapter.messages;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.List;

public class Error {

    public int code;
    public String name;
    public String message;

    @JsonIgnore
    public List<String> error;

    /*

    {
        "code":3010002,
        "name":"account_query_exception",
        "message":"Account Query Exception",
        "stack":[
            {"context":
                {"level":"error",
                "file":"chain_plugin.cpp",
                "line":296,
                "method":"get_abi",
                "hostname":"",
                "thread_name":"thread-0",
                "timestamp":"2018-05-08T21:47:20.662"
                },
            "format":"Fail to retrieve account for ${account}",
            "data":{"account":"initb"}
            }
        ]
    }

     */
}



//{"code":3010002,"name":"account_query_exception","message":"Account Query Exception","stack":[{"context":{"level":"error","file":"chain_plugin.cpp","line":296,"method":"get_abi","hostname":"","thread_name":"thread-0","timestamp":"2018-05-08T21:51:31.493"},"format":"Fail to retrieve account for ${account}","data":{"account":"initb"}}]}
