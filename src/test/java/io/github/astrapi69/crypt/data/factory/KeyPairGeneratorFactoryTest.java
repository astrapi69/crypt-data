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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeySize;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.random.SecureRandomBuilder;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The unit test class for the class {@link KeyPairGeneratorFactory}
 */
class KeyPairGeneratorFactoryTest
{

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testNewKeyPairGeneratorWithECGOST3410()
		throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		KeyPairGenerator keyPairGenerator;
		KeyPair keyPair;
		String stdName;
		// Test with GostR3410-2001-CryptoPro-A
		stdName = "GostR3410-2001-CryptoPro-A";
		keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410", "BC");
		keyPairGenerator.initialize(new ECGenParameterSpec(stdName));

		keyPair = keyPairGenerator.generateKeyPair();
		assertNotNull(keyPair);

		// Test with GostR3410-2001-CryptoPro-B
		stdName = "GostR3410-2001-CryptoPro-B";
		keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410", "BC");
		keyPairGenerator.initialize(new ECGenParameterSpec(stdName));

		keyPair = keyPairGenerator.generateKeyPair();
		assertNotNull(keyPair);

		// Test with GostR3410-2001-CryptoPro-C
		stdName = "GostR3410-2001-CryptoPro-C";
		keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410", "BC");
		keyPairGenerator.initialize(new ECGenParameterSpec(stdName));

		keyPair = keyPairGenerator.generateKeyPair();
		assertNotNull(keyPair);
	}

	/**
	 * Test method for
	 * {@link KeyPairGeneratorFactory#newKeyPairGenerator(String, int, SecureRandom)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyPairGeneratorSpi implementation for the specified
	 *             algorithm
	 */
	@Test
	@DisplayName("Test KeyPairGeneratorFactory with RSA algorithm and key size 2048")
	public void testNewKeyPairGeneratorStringIntSecureRandom() throws NoSuchAlgorithmException
	{
		KeyPairGenerator actual;

		actual = KeyPairGeneratorFactory.newKeyPairGenerator(
			KeyPairGeneratorAlgorithm.RSA.getAlgorithm(), KeySize.KEYSIZE_2048.getKeySize(),
			SecureRandomBuilder.getInstance().build());
		assertNotNull(actual);
		KeyPair keyPair = actual.generateKeyPair();
		String base64 = PrivateKeyExtensions.toBase64(keyPair.getPrivate());
		assertNotNull(base64);
		PrivateKey privateKey = RuntimeExceptionDecorator.decorate(() -> PrivateKeyReader
			.readPemPrivateKey(base64, KeyPairGeneratorAlgorithm.RSA.getAlgorithm()));
		assertNotNull(privateKey);
	}

	/**
	 * Test method for {@link KeyPairGeneratorFactory#newKeyPairGenerator(String, String)}
	 */
	@Test
	@DisplayName("Test KeyPairGeneratorFactory with EC algorithm and BouncyCastle provider")
	public void testNewKeyPairGeneratorWithEC()
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyPairGenerator actual;

		actual = KeyPairGeneratorFactory.newKeyPairGenerator("EC", "BC");
		assertNotNull(actual);
		KeyPair keyPair = actual.generateKeyPair();
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairGeneratorFactory#newKeyPairGenerator(String, int)}
	 */
	@Test
	@DisplayName("Test KeyPairGeneratorFactory with invalid algorithm")
	public void testNewKeyPairGeneratorWithInvalidAlgorithm()
	{
		assertThrows(NoSuchAlgorithmException.class, () -> {
			KeyPairGeneratorFactory.newKeyPairGenerator("INVALID_ALGO", 1024);
		});
	}

	/**
	 * Test method for {@link KeyPairGeneratorFactory} with {@link BeanTester}
	 */
	@Test
	@DisplayName("Test KeyPairGeneratorFactory with BeanTester")
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyPairGeneratorFactory.class);
	}
}
