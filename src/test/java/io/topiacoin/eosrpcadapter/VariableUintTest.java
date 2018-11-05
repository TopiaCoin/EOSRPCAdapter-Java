package io.topiacoin.eosrpcadapter;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static org.junit.Assert.*;

public class VariableUintTest {


    @Test
    public void testUintReadWrite() throws Exception {

        long[] values = new long[] {12, 1234, 123456, 12345678L, 1234567890L, 123456789012L, 12345678901234L, 1234567890123456L, Long.MAX_VALUE} ;

        for ( long value : values ) {
            long readValue = putAndGet(value);
            assertEquals(value, readValue);
        }

        {
            byte[] bs = new byte[]{(byte) 0xec, (byte) 0x95, 0x05};
            ByteBuffer buffer = ByteBuffer.wrap(bs);
            long value = getVariableUInt(buffer);
            System.out.println("Value = " + value);
        }
        {
            byte[] bs = new byte[]{(byte) 0x8a, 0x12};
            ByteBuffer buffer = ByteBuffer.wrap(bs);
            long value = getVariableUInt(buffer);
            System.out.println("Value = " + value);
        }
    }

    public long putAndGet(long value1) {
        ByteBuffer buffer = ByteBuffer.allocate(10);
        putVariableUInt(value1, buffer);
        buffer.flip();
        buffer.mark();
        byte[] readBuffer1 = new byte[buffer.limit()];
        buffer.get(readBuffer1);
        System.out.println ( "Array: " + Hex.encodeHexString(readBuffer1));
        buffer.reset();
        long readValue=getVariableUInt(buffer);
        System.out.println ( "Value: " + readValue);
        System.out.println();
        return readValue;
    }


    public void putVariableUInt(long data, ByteBuffer buffer) {
        do {
            byte b = (byte)(data & 0x7f);
            data >>= 7;
            b |= ((( data > 0) ? 1 : 0) << 7) ;
            buffer.put(b);
        } while ( data > 0) ;
    }

    public long getVariableUInt(ByteBuffer buffer) {
        long value = 0;
        long shift = 0 ;

        byte marker = 0;
        do {
            byte b = buffer.get();
            marker = (byte)(b & 0x80);
            long l = b & 0x7f;
            value |= (l << shift);
            shift += 7;
        } while (marker != 0); //( buffer.hasRemaining() ) ;

        return value;
    }
}
