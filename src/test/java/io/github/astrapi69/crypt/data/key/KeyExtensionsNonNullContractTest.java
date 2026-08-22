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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.Key;
import java.security.KeyPair;
import java.util.function.Function;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;

/**
 * Parameterized tests for the {@link Key} accessors of {@link KeyExtensions} and their non-null
 * contract
 */
class KeyExtensionsNonNullContractTest
{

	private static KeyPair keyPair;

	/**
	 * One accessor
	 *
	 * @param description
	 *            the accessor name
	 * @param accessor
	 *            the accessor under test
	 * @param expected
	 *            the function that yields the expected value directly from the key
	 */
	record AccessorCase(String description, Function<Key, Object> accessor,
		Function<Key, Object> expected) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 1024);
	}

	static Stream<AccessorCase> accessorCases()
	{
		return Stream.of(
			new AccessorCase("getAlgorithm", KeyExtensions::getAlgorithm, Key::getAlgorithm),
			new AccessorCase("getEncoded", KeyExtensions::getEncoded, Key::getEncoded),
			new AccessorCase("getFormat", KeyExtensions::getFormat, Key::getFormat));
	}

	/**
	 * Test method for {@link KeyExtensions#getAlgorithm(Key)},
	 * {@link KeyExtensions#getEncoded(Key)} and {@link KeyExtensions#getFormat(Key)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("accessorCases")
	void accessorDelegatesToKey(final AccessorCase testCase)
	{
		for (Key key : new Key[] { keyPair.getPrivate(), keyPair.getPublic() })
		{
			Object actual = testCase.accessor().apply(key);
			Object expected = testCase.expected().apply(key);
			if (expected instanceof byte[] expectedBytes)
			{
				assertArrayEquals(expectedBytes, (byte[])actual, testCase.description());
			}
			else
			{
				assertEquals(expected, actual, testCase.description());
			}
		}
	}

	/**
	 * Test method for the non-null contract of the accessors
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("accessorCases")
	void accessorRejectsNull(final AccessorCase testCase)
	{
		assertThrows(NullPointerException.class, () -> testCase.accessor().apply(null),
			testCase.description());
	}
}
