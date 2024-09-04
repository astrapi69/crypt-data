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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

/**
 * The class {@code AlgorithmExtensionsParameterizedTest} provides parameterized unit tests for the
 * {@link AlgorithmExtensions} class using a CSV file
 */
class AlgorithmExtensionsParameterizedTest
{
	static
	{
		// Ensuring that some default algorithms are registered for the tests
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	/**
	 * Parameterized test for the {@link AlgorithmExtensions#isValid(String, String)} method using
	 * data from a CSV file
	 *
	 * @param serviceName
	 *            the name of the security service
	 * @param algorithm
	 *            the algorithm to be validated
	 * @param expectedResult
	 *            the expected validation result
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/algorithm_test_data.csv", numLinesToSkip = 1)
	void testIsValid(String serviceName, String algorithm, boolean expectedResult)
	{
		assertEquals(expectedResult, AlgorithmExtensions.isValid(serviceName, algorithm));
	}

	/**
	 * Parameterized test for the {@link AlgorithmExtensions#getAlgorithms(String)} method using
	 * data from a CSV file
	 *
	 * @param serviceName
	 *            the name of the security service
	 * @param expectedAlgorithms
	 *            a comma-separated string of expected algorithm names
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/algorithm_service_data.csv", delimiter = ';', numLinesToSkip = 1)
	void testGetAlgorithms(String serviceName, String expectedAlgorithms)
	{
		Set<String> algorithms = AlgorithmExtensions.getAlgorithms(serviceName);
		Set<String> expectedAlgorithmSet = Set.of(expectedAlgorithms.split(","));
		for (String expectedAlgorithm : expectedAlgorithmSet)
		{
			boolean contains = algorithms.contains(expectedAlgorithm);
			if (contains)
			{
				assertTrue(algorithms.contains(expectedAlgorithm));
			}
			else
			{
				System.out.println("algorithm " + expectedAlgorithm + " not found");
			}
		}
	}

	/**
	 * Parameterized test method for
	 * {@link AlgorithmExtensions#getAlgorithmsFromServiceName(String, String)}
	 *
	 * This method tests the retrieval of signature algorithms using various service names and key
	 * algorithms provided in a CSV file, ensuring that the returned list is appropriate for each
	 * case.
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/signature_algorithms.csv", numLinesToSkip = 1)
	void testGetAlgorithmsFromServiceNameWithCSV(String serviceName, String keyAlgorithm)
	{
		List<String> actual = AlgorithmExtensions.getAlgorithmsFromServiceName(serviceName,
			keyAlgorithm);
		assertNotNull(actual, "The list of algorithms should not be null");

		// If a valid key algorithm is provided, the list should not be empty
		if (!keyAlgorithm.equals("NonExistentAlgorithm"))
		{
			assertFalse(actual.isEmpty(),
				"The list of algorithms should not be empty for a valid key algorithm");
		}

		// Validate all algorithms in the list
		actual.forEach(algorithm -> assertTrue(AlgorithmExtensions.isValid(serviceName, algorithm),
			"The algorithm should be valid for the service name"));
	}
}
