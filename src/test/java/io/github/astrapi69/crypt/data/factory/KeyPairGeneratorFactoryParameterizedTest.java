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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

/**
 * The unit test class for the class {@link KeyPairGeneratorFactory}
 *
 * The unit test class for {@link KeyPairGeneratorFactory} is designed to verify the correctness and
 * robustness of the factory methods for creating {@link KeyPairGenerator} objects. The tests cover
 * various algorithms, including RSA and EC, and use of parameterized test method
 */
class KeyPairGeneratorFactoryParameterizedTest
{

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Test method for {@link KeyPairGeneratorFactory#newKeyPairGenerator(String, String, String)}
	 * with different elliptic curves using a CSV file as a data source
	 *
	 * @param curveName
	 *            the name of the elliptic curve
	 * @param algorithm
	 *            the algorithm
	 * @param provider
	 *            the provider
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyPairGeneratorSpi implementation for the specified
	 *             algorithm
	 * @throws NoSuchProviderException
	 *             if the specified provider is not registered in the security provider list
	 * @throws InvalidAlgorithmParameterException
	 *             if initialization of the cipher object fails
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/ec_curves.csv", numLinesToSkip = 1)
	@DisplayName("Parameterized Test with elliptic curves from CSV file")
	public void testNewKeyPairGeneratorWithECFromCSV(String curveName, String algorithm,
		String provider)
		throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		KeyPairGenerator actual = KeyPairGeneratorFactory.newKeyPairGenerator(curveName, algorithm,
			provider);
		assertNotNull(actual);
		KeyPair keyPair = actual.generateKeyPair();
		assertNotNull(keyPair);
	}

}
