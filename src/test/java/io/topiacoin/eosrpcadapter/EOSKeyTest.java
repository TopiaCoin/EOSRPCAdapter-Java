package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.util.Base58;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import static junit.framework.TestCase.*;

public class EOSKeyTest {

    @BeforeClass
    public static void initClass() throws Exception {
        boolean loaded = false ;
        for (Provider provider : Security.getProviders()) {
            if ( provider instanceof BouncyCastleProvider) {
                loaded = true ;
                break;
            }
        }
        if ( !loaded ) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.println ( "Bouncy Castle Loaded");
        }
    }

    @Test
    public void testEOSKey() throws Exception {
        EOSKey eosKey = EOSKey.randomKey();

        String wif58 = eosKey.toWif();

        System.out.println("WIF58: " + wif58 );
        assertNotNull(wif58);

        String pubKey = eosKey.getPublicKeyString();
        System.out.println("PubKey: " + pubKey) ;

        EOSKey recoverdKey = EOSKey.fromWif(wif58) ;

        assertNotNull ( recoverdKey ) ;

        assertEquals(eosKey, recoverdKey);

        pubKey = recoverdKey.getPublicKeyString();
        System.out.println("PubKey: " + pubKey) ;    }

    @Test
    public void testPublicKeyGeneration() throws Exception {
        String test = "51kdZoTRkCQc7ityw9Jg5LhmFkepq4enjVmQx7cyunQyFUVpz9";
        byte[] testBytes = Base64.decodeBase64(test) ;

        System.out.println (Hex.encodeHexString(testBytes));

        String publicKey = "EOS51kdZoTRkCQc7ityw9Jg5LhmFkepq4enjVmQx7cyunQyFUVpz9";
        String privateKey = "5KTKXhA6QuPFDThASqs1FhQYPaf5P6f9vnAo3bTQvooV93M2oNa";

        EOSKey eosKey = EOSKey.fromWif(privateKey);

        String genPrivKey = eosKey.toWif();
        assertEquals(privateKey, genPrivKey);

        String genPubKey = eosKey.getPublicKeyString();
        assertEquals(publicKey, genPubKey);
    }

}
