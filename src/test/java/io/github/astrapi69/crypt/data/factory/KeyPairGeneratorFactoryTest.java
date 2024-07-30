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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;

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
	 * Test method for
	 * {@link KeyPairGeneratorFactory#newKeyPairGenerator(String, int, SecureRandom)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 */
	@Test
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
	 * Test method for {@link KeyPairGeneratorFactory} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyPairGeneratorFactory.class);
	}
}