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
package io.github.astrapi69.crypt.data.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.github.astrapi69.crypt.data.factory.KeyPairFactory;

/**
 * Test class for {@link KeyPairInfo}.
 */
class KeyPairInfoParameterizedTest
{

	/**
	 * Tests the {@link KeyPairInfo#toKeyPair(KeyPairInfo)} method.
	 *
	 * @param eCNamedCurveParameterSpecName
	 *            the EC named curve parameter specification name
	 * @param algorithm
	 *            the algorithm used for the key pair
	 * @param provider
	 *            the provider of the key pair
	 * @param keySize
	 *            the key size for the key pair
	 * @throws InvalidAlgorithmParameterException
	 *             if initialization of the cipher object fails
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyPairGeneratorSpi implementation for the specified
	 *             algorithm
	 * @throws NoSuchProviderException
	 *             if the specified provider is not registered in the security provider list
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/keypairinfo_test_data.csv", numLinesToSkip = 1)
	void testToKeyPair(String eCNamedCurveParameterSpecName, String algorithm, String provider,
		int keySize)
		throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException
	{

		// Create a KeyPairInfo object from the CSV parameters
		KeyPairInfo keyPairInfo = KeyPairInfo.builder()
			.eCNamedCurveParameterSpecName(eCNamedCurveParameterSpecName).algorithm(algorithm)
			.provider(provider).keySize(keySize).build();

		// Convert KeyPairInfo to KeyPair using the factory method
		KeyPair keyPair = KeyPairFactory.newKeyPair(keyPairInfo);

		// Validate the KeyPair object
		assertNotNull(keyPair);
		assertNotNull(keyPair.getPrivate());
		assertNotNull(keyPair.getPublic());
		assertEquals(algorithm, keyPair.getPrivate().getAlgorithm());
	}

	/**
	 * Tests the {@link KeyPairInfo#toKeyPairInfo(KeyPair)} method.
	 *
	 * @param eCNamedCurveParameterSpecName
	 *            the EC named curve parameter specification name
	 * @param algorithm
	 *            the algorithm used for the key pair
	 * @param provider
	 *            the provider of the key pair
	 * @param keySize
	 *            the key size for the key pair
	 * @throws InvalidAlgorithmParameterException
	 *             if initialization of the cipher object fails
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyPairGeneratorSpi implementation for the specified
	 *             algorithm
	 * @throws NoSuchProviderException
	 *             if the specified provider is not registered in the security provider list
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/keypairinfo_test_data.csv", numLinesToSkip = 1)
	void testToKeyPairInfo(String eCNamedCurveParameterSpecName, String algorithm, String provider,
		int keySize)
		throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException
	{

		// Create a KeyPairInfo object from the CSV parameters
		KeyPairInfo keyPairInfo = KeyPairInfo.builder()
			.eCNamedCurveParameterSpecName(eCNamedCurveParameterSpecName).algorithm(algorithm)
			.provider(provider).keySize(keySize).build();

		// Convert KeyPairInfo to KeyPair using the factory method
		KeyPair keyPair = KeyPairFactory.newKeyPair(keyPairInfo);

		// Convert KeyPair back to KeyPairInfo using the static method
		KeyPairInfo newKeyPairInfo = KeyPairInfo.toKeyPairInfo(keyPair);

		// Validate the new KeyPairInfo object
		assertNotNull(newKeyPairInfo);
		assertEquals(algorithm, newKeyPairInfo.getAlgorithm());
		assertEquals(keySize, newKeyPairInfo.getKeySize());
	}

}
