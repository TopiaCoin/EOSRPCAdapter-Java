package io.topiacoin.eosrpcadapter.messages.abi;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.List;

public class Abi {

	public String ____comment = "";
	public String version = "";

	public List<Struct> structs;
	public List<Type> types;
	public List<Action> actions;
	public List<Table> tables;
	public List<ClausePair> ricardian_clauses;
	public List<String> abi_extensions;
}
