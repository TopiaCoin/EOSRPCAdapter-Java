package io.topiacoin.eosrpcadapter.messages;

import java.util.List;

public class GetCode {

    public static class Request {

        public String account_name;
    }

    public static class Response {
        public String account_name;
        public String name;
        public String code_hash;
        public String wast;
        public ContractABI abi;
    }

    public static class ContractABI {
        public ContractType[] types;
        public ContractStruct[] structs;
        public ContractAction[] actions;
        public ContractTable[] tables;
        public String[] ricardian_clauses;
    }

    public static class ContractType {
        public String new_type_name;
        public String type;
    }

    public static class ContractStruct {
        public String name;
        public String base;
        public ContractField[] fields;
    }

    public static class ContractAction {
        public String name;
        public String type;
        public String ricardian_contract;
    }

    public static class ContractTable{
        public String name ;
        public String type;
        public String index_type;
        public String[] key_names;
        public String[] key_types;
    }

    public static class ContractField {
        public String name;
        public String type;
    }

}
