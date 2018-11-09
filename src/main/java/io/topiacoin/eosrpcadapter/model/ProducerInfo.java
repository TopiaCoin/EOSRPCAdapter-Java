package io.topiacoin.eosrpcadapter.model;

public class ProducerInfo {
	private String _producerName;
	private String _blockSigningKey;

	public ProducerInfo(String producerName, String blockSigningKey) {
		_producerName = producerName;
		_blockSigningKey = blockSigningKey;
	}

	public String getProducerName() {
		return _producerName;
	}

	public void setProducerName(String _producerName) {
		this._producerName = _producerName;
	}

	public String getBlockSigningKey() {
		return _blockSigningKey;
	}

	public void setBlockSigningKey(String _blockSigningKey) {
		this._blockSigningKey = _blockSigningKey;
	}
}
