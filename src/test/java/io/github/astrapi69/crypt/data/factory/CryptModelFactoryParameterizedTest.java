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

import javax.crypto.Cipher;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * The unit test class for the class {@link CryptModelFactory}
 */
public class CryptModelFactoryParameterizedTest
{

	/**
	 * Parameterized test for {@link CryptModelFactory#newCryptModel(Algorithm, String)}
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param key
	 *            the key
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/cryptmodel-test-data.csv", numLinesToSkip = 1)
	public void testNewCryptModelWithAlgorithmAndStringKeyParameterized(String algorithm,
		String key)
	{
		CryptModel<Cipher, String, String> cryptModel;
		Algorithm algo = SunJCEAlgorithm.valueOf(algorithm);
		cryptModel = CryptModelFactory.newCryptModel(algo, key);
		assertNotNull(cryptModel);
	}
}
