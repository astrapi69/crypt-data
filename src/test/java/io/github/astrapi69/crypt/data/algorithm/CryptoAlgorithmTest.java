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
package io.github.astrapi69.crypt.data.algorithm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.meanbean.lang.Factory;
import org.meanbean.test.BeanTester;
import org.meanbean.test.BeanVerifier;

import io.github.astrapi69.crypt.api.algorithm.Algorithm;

/**
 * Test class for the class {@link CryptoAlgorithm}
 */
public class CryptoAlgorithmTest
{

	/**
	 * Test method for {@link CryptoAlgorithm#newAlgorithm(String)}
	 */
	@Test
	public void testNewAlgorithm()
	{
		String name;
		Algorithm interfaceAes;
		String algorithmName;
		String algorithm;
		CryptoAlgorithm aes;
		algorithmName = "AES";
		aes = (CryptoAlgorithm)CryptoAlgorithm.newAlgorithm(algorithmName);
		assertNotNull(aes);
		algorithm = aes.getAlgorithm();
		name = aes.name();
		assertEquals(algorithmName, name);
		assertEquals(algorithm, name);
		interfaceAes = CryptoAlgorithm.newAlgorithm(algorithmName);
		name = interfaceAes.getAlgorithm();
		assertEquals(algorithmName, name);
	}

	/**
	 * Test method for {@link CryptoAlgorithm} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanVerifier.forClass(CryptoAlgorithm.class).editSettings()
			.registerFactory(CryptoAlgorithm.class, new Factory<CryptoAlgorithm>()
			{
				@Override
				public CryptoAlgorithm create()
				{
					return (CryptoAlgorithm)CryptoAlgorithm.newAlgorithm("AES");
				}
			}).edited().verifyGettersAndSetters();

		BeanVerifier.forClass(CryptoAlgorithm.class).editSettings()
			.registerFactory(CryptoAlgorithm.class, () -> {
				return (CryptoAlgorithm)CryptoAlgorithm.newAlgorithm("AES");
			}).edited().verifyGettersAndSetters();

		BeanVerifier.forClass(CryptoAlgorithm.class).editSettings()
			.registerFactory(CryptoAlgorithm.class,
				() -> (CryptoAlgorithm)CryptoAlgorithm.newAlgorithm("AES"))
			.edited().verifyGettersAndSetters();
	}

}
