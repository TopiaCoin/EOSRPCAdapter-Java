package io.topiacoin.eosrpcadapter;

import org.junit.Test;

import static junit.framework.TestCase.*;

public class EOSKeyTest {

    @Test
    public void testEOSKey() throws Exception {
        EOSKey eosKey = EOSKey.randomKey();

        String wif58 = eosKey.toWif();

        System.out.println("WIF58: " + wif58 );
        assertNotNull(wif58);

        EOSKey recoverdKey = EOSKey.fromWif(wif58) ;

        assertNotNull ( recoverdKey ) ;

        assertEquals(eosKey, recoverdKey);
    }
}
