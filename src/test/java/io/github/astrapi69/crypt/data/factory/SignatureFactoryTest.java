/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package io.github.astrapi69.crypt.data.factory;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The unit test class for the class {@link SignatureFactory}
 */
public class SignatureFactoryTest
{

	private static final String ED25519 = "Ed25519";

	private PrivateKey privateKey;
	private PublicKey publicKey;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp() throws Exception
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ED25519);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		privateKey = keyPair.getPrivate();
		publicKey = keyPair.getPublic();
	}

	/**
	 * Test method for {@link SignatureFactory#sign(PrivateKey, String, byte[])} and
	 * {@link SignatureFactory#verify(PublicKey, String, byte[], byte[])}
	 */
	@Test
	public void testSignAndVerify() throws Exception
	{
		byte[] data = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);

		byte[] signature = SignatureFactory.sign(privateKey, ED25519, data);
		assertNotNull(signature);

		boolean verified = SignatureFactory.verify(publicKey, ED25519, data, signature);
		assertTrue(verified);
	}

	/**
	 * Test method for {@link SignatureFactory#verify(PublicKey, String, byte[], byte[])}
	 */
	@Test
	public void testVerifyFailsForTamperedData() throws Exception
	{
		byte[] data = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);
		byte[] tampered = "the quick brown fox jumps over the lazy cat"
			.getBytes(StandardCharsets.UTF_8);

		byte[] signature = SignatureFactory.sign(privateKey, ED25519, data);

		boolean verified = SignatureFactory.verify(publicKey, ED25519, tampered, signature);
		assertFalse(verified);
	}

	/**
	 * Test method for {@link SignatureFactory#verify(PublicKey, String, byte[], byte[])}
	 */
	@Test
	public void testVerifyFailsForTamperedSignature() throws Exception
	{
		byte[] data = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);

		byte[] signature = SignatureFactory.sign(privateKey, ED25519, data);
		signature[0] ^= 0xFF;

		boolean verified = SignatureFactory.verify(publicKey, ED25519, data, signature);
		assertFalse(verified);
	}

}
