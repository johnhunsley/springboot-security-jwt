package com.svlada.security.crypto.password;

import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import static org.springframework.security.crypto.util.EncodingUtils.subArray;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A standard {@code PasswordEncoder} implementation that uses SHA-256 hashing with 1024
 * iterations and a random 8-byte random salt value. It uses an additional system-wide
 * secret value to provide additional protection.
 * <p>
 * The digest algorithm is invoked on the concatenated bytes of the salt, secret and
 * password.
 * <p>
 * If you are developing a new system,
 * {@link org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder} is a better
 * choice both in terms of security and interoperability with other languages.
 *
 * @author Keith Donald
 * @author Luke Taylor
 */
public final class StandardPasswordBase64Encoder implements PasswordEncoder {

    private final Digester digester;

    private final byte[] secret;

    private final BytesKeyGenerator saltGenerator;

    /**
     * Constructs a standard password encoder with no additional secret value.
     */
    public StandardPasswordBase64Encoder() {
        this("");
    }

    /**
     * Constructs a standard password encoder with a secret value which is also included
     * in the password hash.
     *
     * @param secret the secret key used in the encoding process (should not be shared)
     */
    public StandardPasswordBase64Encoder(CharSequence secret) {
        this("SHA-256", secret);
    }

    public String encode(CharSequence rawPassword) {
        return encode(rawPassword, saltGenerator.generateKey());
    }

    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        byte[] digested = decode(encodedPassword);
//        byte[] salt = subArray(digested, 0, saltGenerator.getKeyLength());
//        return matches(digested, digest(rawPassword, salt));
        return matches(encodedPassword.getBytes(), encode(rawPassword).getBytes());
    }

    // internal helpers

    private StandardPasswordBase64Encoder(String algorithm, CharSequence secret) {
        this.digester = new Digester(algorithm, DEFAULT_ITERATIONS);
        this.secret = Utf8.encode(secret);
        this.saltGenerator = KeyGenerators.secureRandom();
    }

    private byte[] sHA1hash(String rawPassword) {
        Hash hash = new Hash(Hash.SHA1_TYPE);
        return hash.hash(rawPassword);
    }

    private String encode(CharSequence rawPassword, byte[] salt) {
//        byte[] digest = digest(rawPassword, salt);
        return new String(Base64.encode(sHA1hash(rawPassword.toString())));
    }

    private byte[] digest(CharSequence rawPassword, byte[] salt) {
        byte[] digest = digester.digest(concatenate(salt, secret,
                Utf8.encode(rawPassword)));
        return concatenate(salt, digest);
    }

    private byte[] decode(CharSequence encodedPassword) {
        return Base64.decode(encodedPassword.toString().getBytes());
    }

    /**
     * Constant time comparison to prevent against timing attacks.
     */
    private boolean matches(byte[] expected, byte[] actual) {
        if (expected.length != actual.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < expected.length; i++) {
            result |= expected[i] ^ actual[i];
        }
        return result == 0;
    }

    private static final int DEFAULT_ITERATIONS = 1024;

    private static MessageDigest createDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No such hashing algorithm", e);
        }
    }

    /**
     *
     */
    final class Digester {

        private final String algorithm;

        private final int iterations;

        /**
         * Create a new Digester.
         * @param algorithm the digest algorithm; for example, "SHA-1" or "SHA-256".
         * @param iterations the number of times to apply the digest algorithm to the input
         */
        public Digester(String algorithm, int iterations) {
            // eagerly validate the algorithm
            createDigest(algorithm);
            this.algorithm = algorithm;
            this.iterations = iterations;
        }

        public byte[] digest(byte[] value) {
            MessageDigest messageDigest = createDigest(algorithm);
            for (int i = 0; i < iterations; i++) {
                value = messageDigest.digest(value);
            }
            return value;
        }
    }
}