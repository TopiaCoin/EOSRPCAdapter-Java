package io.topiacoin.eosrpcadapter.util;

import io.topiacoin.eosrpcadapter.messages.SignedTransaction;
import io.topiacoin.eosrpcadapter.messages.Transaction;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

public class EOSByteWriter {

    private ByteBuffer buffer ;

    public EOSByteWriter(int capacity) {
        this.buffer = ByteBuffer.allocate(capacity);
        this.buffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    public void put(byte data) {
        buffer.put(data);
    }

    public void putShort(short data) {
        buffer.putShort(data);
    }

    public void putInt(int data) {
        buffer.putInt(data);
    }

    public void putLong(long data) {
        buffer.putLong(data);
    }

    public void putBytes(byte[] data) {
        buffer.put(data);
    }

    public void putBytes(byte[] data, int len) {
        buffer.put(data, 0, len);
    }

    public void putBytes(byte[] data, int offset, int len) {
        buffer.put(data, offset, len);
    }

    public byte[] toBytes() {
        buffer.flip();
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        return bytes;
    }

    public int length() {
        return buffer.position();
    }

    public void putString(String data) {
        if ( data.isEmpty() ) {
            putVariableUInt(0);
            return;
        }

        putVariableUInt(data.length()) ;
        putBytes(data.getBytes()) ;
    }

    public void putVariableUInt(long data) {
        do {
            byte b = (byte)(data & 0x7f);
            data >>= 7;
            b |= ((( data > 0) ? 1 : 0) << 7) ;
            put(b);
        } while ( data > 0) ;
    }
}
