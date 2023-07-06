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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

/**
 * The unit test class for the class {@link KeyAgreementFactory}
 */
class KeyAgreementFactoryTest
{

	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newKeyAgreement(PrivateKey, PublicKey, String, String, boolean)}
	 */
	@Test
	void newKeyAgreement() throws Exception
	{
		KeyPairGenerator keyPairGenerator;
		String algorithm = "EC";
		int keySize = 256;
		keyPairGenerator = KeyPairGeneratorFactory.newKeyPairGenerator(algorithm);
		keyPairGenerator.initialize(keySize);

		KeyPair aliceKeyPair = keyPairGenerator.generateKeyPair();

		keyPairGenerator = KeyPairGeneratorFactory.newKeyPairGenerator(algorithm);
		keyPairGenerator.initialize(keySize);
		KeyPair bobKeyPair = keyPairGenerator.generateKeyPair();

		byte[] bobPk = bobKeyPair.getPublic().getEncoded();

		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		X509EncodedKeySpec bobPkSpec = new X509EncodedKeySpec(bobPk);
		PublicKey bobPublicKey = keyFactory.generatePublic(bobPkSpec);

		// Create key agreement
		KeyAgreement aliceKeyAgreement = KeyAgreementFactory
			.newKeyAgreement(aliceKeyPair.getPrivate(), bobPublicKey, "ECDH", null, true);

		assertNotNull(aliceKeyAgreement);
	}

	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newSharedSecret(PrivateKey, PublicKey, String, String, boolean)}
	 */
	@Test
	void newSharedSecret() throws Exception
	{
		KeyPairGenerator keyPairGenerator;
		String algorithm = "EC";
		int keySize = 256;
		keyPairGenerator = KeyPairGeneratorFactory.newKeyPairGenerator(algorithm);
		keyPairGenerator.initialize(keySize);

		KeyPair aliceKeyPair = keyPairGenerator.generateKeyPair();

		keyPairGenerator = KeyPairGeneratorFactory.newKeyPairGenerator(algorithm);
		keyPairGenerator.initialize(keySize);
		KeyPair bobKeyPair = keyPairGenerator.generateKeyPair();

		byte[] bobPk = bobKeyPair.getPublic().getEncoded();

		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		X509EncodedKeySpec bobPkSpec = new X509EncodedKeySpec(bobPk);
		PublicKey bobPublicKey = keyFactory.generatePublic(bobPkSpec);

		KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH");
		aliceKeyAgreement.init(aliceKeyPair.getPrivate());
		aliceKeyAgreement.doPhase(bobPublicKey, true);

		byte[] expected = aliceKeyAgreement.generateSecret();

		byte[] actual = KeyAgreementFactory.newSharedSecret(aliceKeyPair.getPrivate(), bobPublicKey,
			"ECDH", null, true);
		assertNotNull(actual);
		assertArrayEquals(actual, expected);
	}

	/**
	 * Test method for {@link KeyAgreementFactory} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyAgreementFactory.class);
	}
}