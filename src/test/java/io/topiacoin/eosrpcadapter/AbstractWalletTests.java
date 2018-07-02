package io.topiacoin.eosrpcadapter;

import io.topiacoin.eosrpcadapter.messages.Keys;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public abstract class AbstractWalletTests {

    protected abstract Wallet getWallet() ;

    @Test
    public void testWalletList() throws Exception {
        Wallet wallet = getWallet();

        List<String> response = wallet.list();

        assertNotNull(response);
    }

    @Test
    public void testWalletOpen() throws Exception {
        Wallet wallet = getWallet();

        boolean response = wallet.open("default");

        assertTrue(response);
    }

    @Test
    public void testWalletCreate() throws Exception {
        Wallet wallet = getWallet();

        String walletName = "test-" + System.currentTimeMillis();

        String response = wallet.create(walletName);

        assertNotNull(response);
    }

    @Test
    public void testWalletLockUnlockLockAll() throws Exception {
        Wallet wallet = getWallet();

        String walletName = "test-" + System.currentTimeMillis();

        String password = wallet.create(walletName);
        assertNotNull(password);

        List<String> listResponse = wallet.list();
        assertNotNull(listResponse);

        boolean unlockResponse = wallet.unlock(walletName, password);
        assertTrue(unlockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);

        boolean lockResponse = wallet.lock(walletName);
        assertTrue(lockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);

        unlockResponse = wallet.unlock(walletName, password);
        assertTrue(unlockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);

        lockResponse = wallet.lockAll();
        assertTrue(lockResponse);

        listResponse = wallet.list();
        assertNotNull(listResponse);
    }

    @Test
    public void testWalletImportListAndGetPublicKeys() throws Exception {
        Wallet wallet = getWallet();

        String walletName = "test-" + System.currentTimeMillis();

        // Lock all Wallets
        wallet.lockAll();

        // Create a new wallet
        String password = wallet.create(walletName);
        assertNotNull(password);

        // Unlock the new wallet
        boolean unlockResponse = wallet.unlock(walletName, password);
        assertTrue(unlockResponse);

        // List Public Keys in Wallet
        List<String> publicKeys = wallet.getPublicKeys(null);
        assertNotNull(publicKeys);
        assertEquals(1, publicKeys.size());

        // List Keys in wallet
        Keys keysResponse = wallet.listKeys(walletName, password);
        assertNotNull(keysResponse);
        assertNotNull(keysResponse.keys);
        assertEquals(1, keysResponse.keys.size());

        // Create new EOS key
        String privateKey = wallet.createKey();
        assertNotNull (privateKey) ;

        // Import Key into Wallet
        boolean importResponse = wallet.importKey(walletName, privateKey);
        assertTrue(importResponse);

        // List Public Keys in Wallet
        publicKeys = wallet.getPublicKeys(null);
        assertNotNull(publicKeys);
        assertEquals(2, publicKeys.size());

        // List Keys in wallet
        keysResponse = wallet.listKeys(walletName, password);
        assertNotNull(keysResponse);
        assertNotNull(keysResponse.keys);
        assertEquals(2, keysResponse.keys.size());
    }

    @Test
    public void testWalletSetTimeout() throws Exception {
        Wallet wallet = getWallet();

        boolean response = wallet.setTimeout(null, 3600);

        assertTrue(response);
    }

}
