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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.key.KeySizeInitializer;

/**
 * Parameterized tests for
 * {@link AlgorithmExtensions#getSupportedAlgorithmsAndKeySizes(String, Class, KeySizeInitializer, int, int, int)}
 * and for the non-null contract of the {@link AlgorithmExtensions} methods
 */
class AlgorithmExtensionsKeySizesParameterizedTest
{

	/**
	 * One probing run: the probe accepts a single algorithm with the given key sizes
	 *
	 * @param serviceName
	 *            the service whose algorithms are probed
	 * @param acceptedAlgorithm
	 *            the only algorithm the probe accepts
	 * @param acceptedKeySizes
	 *            the key sizes the probe accepts for that algorithm
	 * @param minSize
	 *            the lower bound of the probed range
	 * @param maxSize
	 *            the upper bound of the probed range
	 * @param increment
	 *            the step of the probed range
	 * @param expectedKeySizes
	 *            the key sizes that must be reported for the accepted algorithm
	 */
	record SupportedKeySizesCase(String serviceName, String acceptedAlgorithm,
		int[] acceptedKeySizes, int minSize, int maxSize, int increment,
		Set<Integer> expectedKeySizes) {
	}

	/**
	 * One call with a null argument
	 *
	 * @param description
	 *            what is passed as null
	 * @param call
	 *            the call
	 */
	record NullArgumentCase(String description, Executable call) {
	}

	@BeforeAll
	static void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	static Stream<SupportedKeySizesCase> supportedKeySizesCases()
	{
		return Stream.of(
			new SupportedKeySizesCase("KeyPairGenerator", "RSA", new int[] { 512, 1024 }, 512, 1024,
				512, Set.of(512, 1024)),
			new SupportedKeySizesCase("KeyPairGenerator", "EC", new int[] { 256 }, 128, 512, 128,
				Set.of(256)),
			new SupportedKeySizesCase("KeyGenerator", "AES", new int[] { 128, 192, 256 }, 64, 256,
				64, Set.of(128, 192, 256)),
			// the accepted key size lies outside of the probed range
			new SupportedKeySizesCase("KeyPairGenerator", "RSA", new int[] { 4096 }, 512, 1024, 512,
				Set.of()));
	}

	/**
	 * Test method for
	 * {@link AlgorithmExtensions#getSupportedAlgorithmsAndKeySizes(String, Class, KeySizeInitializer, int, int, int)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the reflective probing fails
	 */
	@ParameterizedTest
	@MethodSource("supportedKeySizesCases")
	void getSupportedAlgorithmsAndKeySizes(final SupportedKeySizesCase testCase) throws Exception
	{
		Map<String, Set<Integer>> actual = AlgorithmExtensions.getSupportedAlgorithmsAndKeySizes(
			testCase.serviceName(), KeySizeProbe.class,
			KeySizeProbe.accepting(testCase.acceptedAlgorithm(), testCase.acceptedKeySizes()),
			testCase.minSize(), testCase.maxSize(), testCase.increment());

		// every registered algorithm of the service is probed, nothing else
		assertEquals(AlgorithmExtensions.getAlgorithms(testCase.serviceName()), actual.keySet());
		assertEquals(testCase.expectedKeySizes(), actual.get(testCase.acceptedAlgorithm()));
		actual.forEach((algorithm, keySizes) -> {
			if (!algorithm.equals(testCase.acceptedAlgorithm()))
			{
				assertTrue(keySizes.isEmpty(), algorithm + " must not report key sizes");
			}
		});
	}

	/**
	 * Test method for
	 * {@link AlgorithmExtensions#getSupportedAlgorithmsAndKeySizes(String, Class, KeySizeInitializer, int, int, int)}
	 * with a service that has no algorithms
	 *
	 * @throws Exception
	 *             if the reflective probing fails
	 */
	@Test
	void getSupportedAlgorithmsAndKeySizesWithUnknownService() throws Exception
	{
		Map<String, Set<Integer>> actual = AlgorithmExtensions.getSupportedAlgorithmsAndKeySizes(
			"NoSuchService", KeySizeProbe.class, KeySizeProbe.accepting("RSA", 512), 512, 512, 1);

		assertTrue(actual.isEmpty());
	}

	static Stream<NullArgumentCase> nullArgumentCases()
	{
		return Stream.of(
			new NullArgumentCase("getAlgorithmsFromServiceName: service name",
				() -> AlgorithmExtensions.getAlgorithmsFromServiceName(null, "RSA")),
			new NullArgumentCase("getAlgorithmsFromServiceName: key algorithm",
				() -> AlgorithmExtensions.getAlgorithmsFromServiceName("Signature", null)),
			new NullArgumentCase("isValid: service name",
				() -> AlgorithmExtensions.isValid(null, "AES")),
			new NullArgumentCase("isValid: algorithm",
				() -> AlgorithmExtensions.isValid("Cipher", null)),
			new NullArgumentCase("getAlgorithms: service name",
				() -> AlgorithmExtensions.getAlgorithms(null)),
			new NullArgumentCase("getServiceNames: provider",
				() -> AlgorithmExtensions.getServiceNames(null)));
	}

	/**
	 * Test method for the non-null contract of the {@link AlgorithmExtensions} methods
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("nullArgumentCases")
	void nonNullContract(final NullArgumentCase testCase)
	{
		assertThrows(NullPointerException.class, testCase.call(), testCase.description());
	}
}
