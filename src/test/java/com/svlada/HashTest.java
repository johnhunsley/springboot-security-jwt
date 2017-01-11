package com.svlada;

import com.svlada.security.crypto.password.Hash;
import org.junit.Test;

import java.lang.String;import java.lang.System;import java.util.Base64;

/**
 * @author John Hunsley
 *         jphunsley@gmail.com
 *         Date : 11/01/2017
 *         Time : 16:02
 */
public class HashTest {


    @Test
    public void testHash() {
        final String value = "password";
        Hash hash = new Hash(Hash.SHA1_TYPE);
        byte[] hashed = Base64.getEncoder().encode(hash.hash(value));
        System.out.println(new String(hashed));
    }
}
