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

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm;

/**
 * The unit test class for the class {@link SecretKeyFactoryExtensions}
 */
public class SecretKeyFactoryExtensionsTest
{

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKey(char[], String)}
	 */
	@Test
	public void testNewSecretKey() throws Exception
	{
		String algorithm;
		SecretKey secretKey;

		algorithm = SunJCEAlgorithm.PBEWithMD5AndDES.getAlgorithm();
		secretKey = SecretKeyFactoryExtensions.newSecretKey("secret".toCharArray(), algorithm);
		assertNotNull(secretKey);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKeyFactory(String)}
	 */
	@Test
	public void testNewSecretKeyFactory() throws Exception
	{
		String algorithm;
		SecretKeyFactory secretKeyFactory;

		algorithm = CompoundAlgorithm.PBE_WITH_MD5_AND_DES.getAlgorithm();
		secretKeyFactory = SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm);
		assertNotNull(secretKeyFactory);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKey(String, int)}
	 */
	@Test
	public void testNewSecretKeyWithKeyLength() throws Exception
	{
		String algorithm = "AES";
		int keyLength = 256;
		SecretKey secretKey = SecretKeyFactoryExtensions.newSecretKey(algorithm, keyLength);
		assertNotNull(secretKey);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKey(byte[], String)}
	 */
	@Test
	public void testNewSecretKeyWithByteArray() throws Exception
	{
		byte[] sharedSecret = ArrayFactory.newByteArray(100, 13, -105, 60, -120, -31, -120, 48, 40,
			-13, -42, -102, -6, -103, 55, -50, 95, 104, -63, 98, -35, -104, -78, 122, -27, 45, -52,
			-6, 29, -51, 44, -70);
		String algorithm = "DES";
		SecretKey secretKey = SecretKeyFactoryExtensions.newSecretKey(sharedSecret, algorithm);
		assertNotNull(secretKey);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(SecretKeyFactoryExtensions.class);
	}
}
