package io.topiacoin.eosrpcadapter.messages;

import java.util.List;
import java.util.Map;

public class Action {

    public String account;
    public String name;
    public List<Transaction.Authorization> authorizations;
    public Map<String,Object> args;

    public Action() {
    }

    public Action(String account,
                  String name,
                  List<Transaction.Authorization> authorizations,
                  Map<String, Object> args) {
        this.account = account;
        this.name = name;
        this.authorizations = authorizations;
        this.args = args;
    }

}
