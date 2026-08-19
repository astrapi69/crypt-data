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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.KEM;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The unit test class for the class {@link KemFactory}
 */
public class KemFactoryTest
{

	private static final String ML_KEM_768 = "ML-KEM-768";

	private PrivateKey privateKey;
	private PublicKey publicKey;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ML_KEM_768, "BC");
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		privateKey = keyPair.getPrivate();
		publicKey = keyPair.getPublic();
	}

	/**
	 * Test method for {@link KemFactory#encapsulate(PublicKey, String)} and
	 * {@link KemFactory#decapsulate(PrivateKey, byte[], String)}
	 */
	@Test
	public void testEncapsulateAndDecapsulate() throws Exception
	{
		final KEM.Encapsulated encapsulated = KemFactory.encapsulate(publicKey, ML_KEM_768);
		assertNotNull(encapsulated);
		final SecretKey senderSecret = encapsulated.key();
		assertNotNull(senderSecret);

		final SecretKey receiverSecret = KemFactory.decapsulate(privateKey,
			encapsulated.encapsulation(), ML_KEM_768);

		assertArrayEquals(senderSecret.getEncoded(), receiverSecret.getEncoded());
	}

	/**
	 * Test method for {@link KemFactory#encapsulate(PublicKey, String)} confirming two
	 * encapsulations produce different ciphertexts and secrets (fresh randomness per call)
	 */
	@Test
	public void testEncapsulateIsNonDeterministic() throws Exception
	{
		final KEM.Encapsulated first = KemFactory.encapsulate(publicKey, ML_KEM_768);
		final KEM.Encapsulated second = KemFactory.encapsulate(publicKey, ML_KEM_768);

		final boolean sameSecret = java.util.Arrays.equals(first.key().getEncoded(),
			second.key().getEncoded());
		final boolean sameCiphertext = java.util.Arrays.equals(first.encapsulation(),
			second.encapsulation());

		org.junit.jupiter.api.Assertions.assertFalse(sameSecret);
		org.junit.jupiter.api.Assertions.assertFalse(sameCiphertext);
	}

}
