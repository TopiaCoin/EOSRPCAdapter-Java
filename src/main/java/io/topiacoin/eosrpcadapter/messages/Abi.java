package io.topiacoin.eosrpcadapter.messages;

import io.topiacoin.eosrpcadapter.util.Base32;
import io.topiacoin.eosrpcadapter.util.EOSByteWriter;

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
	public List<Variant> variants = null;

	public void pack(EOSByteWriter byteWriter) {
		//(version)(types)(structs)(actions)(tables)(ricardian_clauses)(error_messages)(abi_extensions)(variants)
		byte[] versionData = version.getBytes();
		byteWriter.putVariableUInt(versionData.length);
		byteWriter.putBytes(versionData);

		byteWriter.putVariableUInt(types.size());
		for (Type type : types) {
			type.pack(byteWriter);
		}

		byteWriter.putVariableUInt(structs.size());
		for (Struct struct : structs) {
			struct.pack(byteWriter);
		}

		byteWriter.putVariableUInt(actions.size());
		for (Action action : actions) {
			action.pack(byteWriter);
		}

		byteWriter.putVariableUInt(tables.size());
		for (Table table : tables) {
			table.pack(byteWriter);
		}

		byteWriter.putVariableUInt(ricardian_clauses.size());
		for (ClausePair clause : ricardian_clauses) {
			clause.pack(byteWriter);
		}

		byteWriter.putVariableUInt(0); //Error Messages size is always 0 because :shrug:

		byteWriter.putVariableUInt(abi_extensions.size());
		if (!abi_extensions.isEmpty()) {
			//Sorry, I don't have an example of what these look like, so writing a pack method is kind of difficult.
			//Feel free to implement it if you need to
			throw new UnsupportedOperationException("ABI Extensions are unsupported");
		}

		if (variants != null && !variants.isEmpty()) {
			byteWriter.putVariableUInt(variants.size());
			for (Variant variant : variants) {
				variant.pack(byteWriter);
			}
		} else {
			byteWriter.putVariableUInt(0);
		}

	}

	public static class Action {
		public String name;
		public String type;
		public String ricardian_contract;

		public void pack(EOSByteWriter byteWriter) {
			long nameBytes = Base32.decode(name);
			byteWriter.putLong(nameBytes);

			byte[] typeBytes = type.getBytes();
			byteWriter.putVariableUInt(typeBytes.length);
			byteWriter.putBytes(typeBytes);

			byte[] contractBytes = ricardian_contract.getBytes();
			byteWriter.putVariableUInt(contractBytes.length);
			byteWriter.putBytes(contractBytes);
		}
	}

	public static class Type {
		public String new_type_name;
		public String type;

		public void pack(EOSByteWriter byteWriter) {
			byte[] newTypeName = new_type_name.getBytes();
			byteWriter.putVariableUInt(newTypeName.length);
			byteWriter.putBytes(newTypeName);

			byte[] typeBytes = type.getBytes();
			byteWriter.putVariableUInt(typeBytes.length);
			byteWriter.putBytes(typeBytes);
		}
	}

	public static class Table {
		public String name;
		public String index_type;
		public List<String> key_names;
		public List<String> key_types;
		public String type;

		public void pack(EOSByteWriter byteWriter) {
			long nameBytes = Base32.decode(name);
			byteWriter.putLong(nameBytes);

			byte[] indextypeBytes = index_type.getBytes();
			byteWriter.putVariableUInt(indextypeBytes.length);
			byteWriter.putBytes(indextypeBytes);

			byteWriter.putVariableUInt(key_names.size());
			for (String keyName : key_names) {
				byte[] keyNameBytes = keyName.getBytes();
				byteWriter.putVariableUInt(keyNameBytes.length);
				byteWriter.putBytes(keyNameBytes);
			}

			byteWriter.putVariableUInt(key_types.size());
			for (String keyType : key_types) {
				byte[] keyTypeBytes = keyType.getBytes();
				byteWriter.putVariableUInt(keyTypeBytes.length);
				byteWriter.putBytes(keyTypeBytes);
			}

			byte[] typeBytes = type.getBytes();
			byteWriter.putVariableUInt(typeBytes.length);
			byteWriter.putBytes(typeBytes);
		}
	}

	public static class ClausePair {
		public String id;
		public String body;

		public void pack(EOSByteWriter byteWriter) {
			byte[] idBytes = id.getBytes();
			byteWriter.putVariableUInt(idBytes.length);
			byteWriter.putBytes(idBytes);

			byte[] bodyBytes = body.getBytes();
			byteWriter.putVariableUInt(bodyBytes.length);
			byteWriter.putBytes(bodyBytes);
		}
	}

	public static class Field {
		public String name;
		public String type;

		public void pack(EOSByteWriter byteWriter) {
			byte[] nameBytes = name.getBytes();
			byteWriter.putVariableUInt(nameBytes.length);
			byteWriter.putBytes(nameBytes);

			byte[] typeBytes = type.getBytes();
			byteWriter.putVariableUInt(typeBytes.length);
			byteWriter.putBytes(typeBytes);
		}
	}

	public static class Struct {
		public String name;
		public String base;
		public List<Field> fields;

		public void pack(EOSByteWriter byteWriter) {
			byte[] nameBytes = name.getBytes();
			byteWriter.putVariableUInt(nameBytes.length);
			byteWriter.putBytes(nameBytes);

			byte[] baseBytes = base.getBytes();
			byteWriter.putVariableUInt(baseBytes.length);
			byteWriter.putBytes(baseBytes);

			byteWriter.putVariableUInt(fields.size());
			for (Field field : fields) {
				field.pack(byteWriter);
			}
		}
	}

	public static class Variant {
		public String name;
		public List<String> types;

		public void pack(EOSByteWriter byteWriter) {
			byte[] nameBytes = name.getBytes();
			byteWriter.putVariableUInt(nameBytes.length);
			byteWriter.putBytes(nameBytes);

			byteWriter.putVariableUInt(types.size());
			for (String type : types) {
				byte[] typeBytes = type.getBytes();
				byteWriter.putVariableUInt(typeBytes.length);
				byteWriter.putBytes(typeBytes);
			}
		}
	}
}