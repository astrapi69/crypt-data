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

import java.security.NoSuchProviderException;

import javax.crypto.SecretKeyFactory;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

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
		SecretKeyFactory secretKeyFactory;

		algorithm = SunJCEAlgorithm.PBEWithMD5AndDES.getAlgorithm();
		secretKeyFactory = SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm);
		assertNotNull(secretKeyFactory);
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
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKeyFactory(String, String)}
	 */
	@Test
	public void testNewSecretKeyFactoryWithProvider() throws Exception
	{
		String algorithm = CompoundAlgorithm.PBE_WITH_MD5_AND_DES.getAlgorithm();
		String provider = "SunJCE";
		SecretKeyFactory secretKeyFactory;

		// Test with a valid provider
		secretKeyFactory = SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm, provider);
		assertNotNull(secretKeyFactory);

		// Test with null provider
		secretKeyFactory = SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm, null);
		assertNotNull(secretKeyFactory);

		// Test with empty provider
		secretKeyFactory = SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm, "");
		assertNotNull(secretKeyFactory);

		// Test with invalid provider
		String invalidProvider = "InvalidProvider";
		assertThrows(NoSuchProviderException.class, () -> {
			SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm, invalidProvider);
		});
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
