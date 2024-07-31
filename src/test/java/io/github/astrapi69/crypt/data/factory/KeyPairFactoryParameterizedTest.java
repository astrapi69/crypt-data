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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;


/**
 * The unit test class for the class {@link KeyPairFactory}
 */
public class KeyPairFactoryParameterizedTest
{

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@BeforeEach
	protected void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Parameterized test method for {@link KeyPairFactory#newKeyPair(String, int)}
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/keypair_test_data.csv", numLinesToSkip = 1)
	public void testNewKeyPairParameterized(String algorithm, int keySize)
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyPair keyPair = KeyPairFactory.newKeyPair(algorithm, keySize);
		assertNotNull(keyPair);
	}
}
