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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.Algorithm;

/**
 * Parameterized tests for the factory method and the non-null contract of {@link CryptoAlgorithm}
 */
class CryptoAlgorithmNonNullContractTest
{

	/**
	 * One algorithm name
	 *
	 * @param algorithm
	 *            the algorithm name
	 * @param other
	 *            a different algorithm name
	 */
	record AlgorithmCase(String algorithm, String other) {
	}

	static Stream<AlgorithmCase> algorithmCases()
	{
		return Stream.of(new AlgorithmCase("AES", "RSA"), new AlgorithmCase("SHA256withRSA", "EC"),
			new AlgorithmCase("", "AES"));
	}

	/**
	 * Test method for {@link CryptoAlgorithm#newAlgorithm(String)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("algorithmCases")
	void newAlgorithm(final AlgorithmCase testCase)
	{
		Algorithm actual = CryptoAlgorithm.newAlgorithm(testCase.algorithm());

		assertEquals(testCase.algorithm(), actual.getAlgorithm());
		assertEquals(testCase.algorithm(), ((CryptoAlgorithm)actual).name());
		// value semantics: same name is equal, different name is not
		assertEquals(actual, CryptoAlgorithm.newAlgorithm(testCase.algorithm()));
		assertEquals(actual.hashCode(),
			CryptoAlgorithm.newAlgorithm(testCase.algorithm()).hashCode());
		assertNotEquals(actual, CryptoAlgorithm.newAlgorithm(testCase.other()));
	}

	/**
	 * Test method for {@link CryptoAlgorithm#newAlgorithm(String)} with null
	 */
	@Test
	void newAlgorithmWithNull()
	{
		assertThrows(NullPointerException.class, () -> CryptoAlgorithm.newAlgorithm(null));
	}
}
