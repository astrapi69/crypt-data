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
package io.github.astrapi69.crypt.data.key;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.util.Set;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

/**
 * The parameterized unit test class for the class {@link KeySizeExtensions}
 */
class KeySizeExtensionsParameterizedTest
{
	/**
	 * Test method for {@link KeySizeExtensions#getSupportedKeySizesForKeyPairGenerator(String)}
	 * with parameterized input from a CSV file
	 *
	 * @param serviceName
	 *            the cryptographic service name
	 * @param algorithm
	 *            the cryptographic algorithm
	 * @throws NoSuchAlgorithmException
	 *             if the specified algorithm is not available
	 * @throws NoSuchMethodException
	 *             if the specified method cannot be found
	 * @throws InvocationTargetException
	 *             if the underlying method throws an exception
	 * @throws IllegalAccessException
	 *             if the method is inaccessible
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/key-size-resolver-data.csv", numLinesToSkip = 1)
	void testGetSupportedKeySizes(String serviceName, String algorithm)
		throws NoSuchAlgorithmException, NoSuchMethodException, InvocationTargetException,
		IllegalAccessException
	{
		Set<Integer> supportedKeySizes = null;

		switch (serviceName)
		{
			case "KeyPairGenerator" :
				supportedKeySizes = KeySizeExtensions
					.getSupportedKeySizesForKeyPairGenerator(algorithm);
				break;

			case "KeyGenerator" :
				supportedKeySizes = KeySizeExtensions
					.getSupportedKeySizesForKeyGenerator(algorithm);
				break;

			case "AlgorithmParameterGenerator" :
				supportedKeySizes = KeySizeExtensions
					.getSupportedKeySizesForAlgorithmParameterGenerator(algorithm);
				break;

			default :
				fail("Unsupported service name: " + serviceName);
		}

		assertNotNull(supportedKeySizes,
			"The result should not be null for " + serviceName + " and algorithm " + algorithm);
		assertFalse(supportedKeySizes.isEmpty(), "Supported key sizes should not be empty for "
			+ serviceName + " and algorithm " + algorithm);
	}

	/**
	 * Edge case test method for
	 * {@link KeySizeExtensions#getSupportedKeySizesForKeyPairGenerator(String)} with boundary
	 * values from a CSV file
	 *
	 * @param algorithm
	 *            the cryptographic algorithm
	 * @throws NoSuchAlgorithmException
	 *             if the specified algorithm is not available
	 * @throws NoSuchMethodException
	 *             if the specified method cannot be found
	 * @throws InvocationTargetException
	 *             if the underlying method throws an exception
	 * @throws IllegalAccessException
	 *             if the method is inaccessible
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/test-data-edge-cases.csv", numLinesToSkip = 1)
	void testKeyPairGeneratorEdgeCases(String algorithm) throws NoSuchAlgorithmException,
		NoSuchMethodException, InvocationTargetException, IllegalAccessException
	{
		Set<Integer> keySizes = KeySizeExtensions
			.getSupportedKeySizesForKeyPairGenerator(algorithm);
		if (algorithm.equals("DSA"))
		{
			assertNotNull(keySizes,
				"The result should not be null for KeyPairGenerator and algorithm " + algorithm);
			assertFalse(keySizes.contains(511),
				"KeyPairGenerator should not support 511-bit keys for " + algorithm);
			assertTrue(keySizes.contains(512),
				"KeyPairGenerator should support 512-bit keys for " + algorithm);
			assertTrue(keySizes.contains(3072),
				"KeyPairGenerator should support 3072-bit keys for " + algorithm);
			assertFalse(keySizes.contains(3073),
				"KeyPairGenerator should not support 3073-bit keys for " + algorithm);
		}
		else if (algorithm.equals("RSA") || algorithm.equals("DIFFIEHELLMAN"))
		{
			assertNotNull(keySizes,
				"The result should not be null for KeyPairGenerator and algorithm " + algorithm);
			assertFalse(keySizes.contains(511),
				"KeyPairGenerator should not support 511-bit keys for " + algorithm);
			assertTrue(keySizes.contains(512),
				"KeyPairGenerator should support 512-bit keys for " + algorithm);
			assertTrue(keySizes.contains(8192),
				"KeyPairGenerator should support 8192-bit keys for " + algorithm);
			assertFalse(keySizes.contains(8193),
				"KeyPairGenerator should not support 8193-bit keys for " + algorithm);
		}
	}

}
