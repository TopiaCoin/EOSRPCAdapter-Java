package io.topiacoin.eosrpcadapter.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class EOSByteWriter {

    private ByteBuffer buffer ;

    public EOSByteWriter(int capacity) {
        this.buffer = ByteBuffer.allocate(capacity);
        this.buffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    public void put(byte data) {
        expandBufferIfNecessary(1);
        buffer.put(data);
    }

    public void putShort(short data) {
        expandBufferIfNecessary(2);
        buffer.putShort(data);
    }

    public void putInt(int data) {
        expandBufferIfNecessary(4);
        buffer.putInt(data);
    }

    public void putLong(long data) {
        expandBufferIfNecessary(8);
        buffer.putLong(data);
    }

    public void putBytes(byte[] data) {
        expandBufferIfNecessary(data.length);
        buffer.put(data);
    }

    public void putBytes(byte[] data, int len) {
        expandBufferIfNecessary(len);
        buffer.put(data, 0, len);
    }

    public void putBytes(byte[] data, int offset, int len) {
        expandBufferIfNecessary(len);
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
        expandBufferIfNecessary(10 + data.length());
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

    private void expandBufferIfNecessary(int dataLen) {
        if(buffer.remaining() < dataLen) {
            ByteBuffer expandedBuffer = ByteBuffer.allocate((int) (buffer.capacity() + Math.max(buffer.capacity() / 2, dataLen * 1.1)));
            expandedBuffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.flip();
            expandedBuffer.put(buffer);
            buffer = expandedBuffer;
        }
    }
}
