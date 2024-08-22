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

import static org.junit.jupiter.api.Assertions.*;

import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.provider.SecurityProvider;

/**
 * The class {@code AlgorithmExtensionsTest} provides unit tests for the {@link AlgorithmExtensions}
 * class
 */
class AlgorithmExtensionsTest
{
	@BeforeAll
	static void setUp()
	{
		// Ensuring that some default algorithms are registered for the tests
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	/**
	 * Test for a valid algorithm
	 */
	@Test
	void testIsValid()
	{
		assertTrue(AlgorithmExtensions.isValid("Cipher", "AES"));
	}

	/**
	 * Test for an invalid algorithm
	 */
	@Test
	void testIsInvalid()
	{
		assertFalse(AlgorithmExtensions.isValid("Cipher", "InvalidAlgorithm"));
	}

	/**
	 * Test for an invalid service name
	 */
	@Test
	void testInvalidService()
	{
		assertFalse(AlgorithmExtensions.isValid("InvalidService", "AES"));
	}

	/**
	 * Test method for {@link AlgorithmExtensions#getAlgorithmsFromServiceName(String, String)}
	 *
	 * This method tests the retrieval of signature algorithms for a given key algorithm, ensuring
	 * that the returned list is not null and that all algorithms are valid for the specified
	 * service name.
	 */
	@Test
	void testGetAlgorithmsFromServiceName()
	{
		List<String> actual;
		String serviceName;
		String keyAlgorithm;

		// Test with RSA
		serviceName = "Signature";
		keyAlgorithm = "RSA";
		actual = AlgorithmExtensions.getAlgorithmsFromServiceName(serviceName, keyAlgorithm);
		assertNotNull(actual);
		assertFalse(actual.isEmpty(), "The list of algorithms should not be empty");
		actual
			.forEach(algorithm -> assertTrue(AlgorithmExtensions.isValid(serviceName, algorithm)));

		// Test with an algorithm that should not return any result
		keyAlgorithm = "NonExistentAlgorithm";
		actual = AlgorithmExtensions.getAlgorithmsFromServiceName(serviceName, keyAlgorithm);
		assertNotNull(actual);
		assertTrue(actual.isEmpty(),
			"The list of algorithms should be empty for an invalid key algorithm");
	}

	/**
	 * Test for retrieving algorithms for a valid service
	 */
	@Test
	void testGetAlgorithms()
	{
		Set<String> algorithms = AlgorithmExtensions.getAlgorithms("Cipher");
		assertNotNull(algorithms);
		assertTrue(algorithms.contains("AES"));
	}

	/**
	 * Test for retrieving algorithms for a valid service of Signature
	 */
	@Test
	void testGetAlgorithmsFromSignature()
	{
		Set<String> signatureAlgorithms = AlgorithmExtensions.getAlgorithms("Signature");
		assertNotNull(signatureAlgorithms);
		assertTrue(signatureAlgorithms.contains("SHA1withRSA".toUpperCase()));
	}


	/**
	 * Test for retrieving algorithms for a valid service of KeyPairGenerator
	 */
	@Test
	void testGetAlgorithmsFromKeyPairGenerator()
	{
		Set<String> keyPairGeneratorAlgorithms = AlgorithmExtensions
			.getAlgorithms("KeyPairGenerator");
		assertNotNull(keyPairGeneratorAlgorithms);
		assertTrue(keyPairGeneratorAlgorithms.contains("RSA".toUpperCase()));
	}

	/**
	 * Test for retrieving algorithms for an invalid service
	 */
	@Test
	void testGetAlgorithmsInvalidService()
	{
		Set<String> algorithms = AlgorithmExtensions.getAlgorithms("InvalidService");
		assertNotNull(algorithms);
		assertTrue(algorithms.isEmpty());
	}

	/**
	 * Test for retrieving service names from a provider
	 */
	@Test
	void testGetServiceNames()
	{
		Provider provider = Security.getProvider(SecurityProvider.BC.name());
		Set<String> serviceNames = AlgorithmExtensions.getServiceNames(provider);
		assertNotNull(serviceNames);
		assertTrue(serviceNames.contains("Cipher"));
	}

	/**
	 * Test for retrieving all service names from providers
	 */
	@Test
	void testGetAllServiceNames()
	{
		Provider[] providers = Security.getProviders();
		Set<String> serviceNames = AlgorithmExtensions.getAllServiceNames(providers);
		assertNotNull(serviceNames);
		assertTrue(serviceNames.contains("Cipher"));
	}

	/**
	 * Test method for {@link AlgorithmExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(AlgorithmExtensions.class);
	}

}
