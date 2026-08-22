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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized tests for {@link KeyPairInfo#isValid(KeyPairInfo)} and the non-null contract of the
 * static {@link KeyPairInfo} methods
 */
class KeyPairInfoValidationParameterizedTest
{

	/**
	 * One validation
	 *
	 * @param algorithm
	 *            the algorithm name
	 * @param keySize
	 *            the key size
	 * @param expected
	 *            the expected validation result
	 */
	record IsValidCase(String algorithm, int keySize, boolean expected) {
	}

	/**
	 * One call with a null argument
	 *
	 * @param description
	 *            the called method
	 * @param call
	 *            the call
	 */
	record NullArgumentCase(String description, Executable call) {
	}

	static Stream<IsValidCase> isValidCases()
	{
		return Stream.of(
			// registered algorithm + supported key size -> valid for creation
			new IsValidCase("RSA", 2048, true), new IsValidCase("RSA", 1024, true),
			new IsValidCase("EC", 256, true),
			// registered algorithm but a key size no provider supports (RSA minimum is 512)
			new IsValidCase("RSA", 100, false),
			// Security.getAlgorithms reports upper-case names only, so a mis-cased name is not a
			// registered KeyPairGenerator algorithm and is rejected before any key size probing
			new IsValidCase("rsa", 2048, false),
			// not an algorithm at all
			new IsValidCase("NOT-AN-ALGORITHM", 2048, false));
	}

	/**
	 * Test method for {@link KeyPairInfo#isValid(KeyPairInfo)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the key size probing fails
	 */
	@ParameterizedTest
	@MethodSource("isValidCases")
	void isValid(final IsValidCase testCase) throws Exception
	{
		KeyPairInfo keyPairInfo = KeyPairInfo.builder().algorithm(testCase.algorithm())
			.keySize(testCase.keySize()).build();

		assertEquals(testCase.expected(), KeyPairInfo.isValid(keyPairInfo), testCase.toString());
	}

	static Stream<NullArgumentCase> nullArgumentCases()
	{
		return Stream.of(new NullArgumentCase("toKeyPair", () -> KeyPairInfo.toKeyPair(null)),
			new NullArgumentCase("toKeyPairInfo", () -> KeyPairInfo.toKeyPairInfo(null)),
			new NullArgumentCase("isValid", () -> KeyPairInfo.isValid(null)), new NullArgumentCase(
				"builder without algorithm", () -> KeyPairInfo.builder().keySize(2048).build()));
	}

	/**
	 * Test method for the non-null contract of the static {@link KeyPairInfo} methods
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
