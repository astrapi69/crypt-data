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
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/key-size-resolver-data.csv", numLinesToSkip = 1)
	void testGetSupportedKeySizes(String serviceName, String algorithm)
		throws NoSuchAlgorithmException, InvocationTargetException, NoSuchMethodException,
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
}
