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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.stream.Stream;

import javax.crypto.SecretKey;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized test for {@link SecretKeyFactoryExtensions#newSecretKey(String, int)}: the
 * requested key length must be honoured, so the generator really is initialized with it
 */
class SecretKeyFactoryExtensionsKeyLengthParameterizedTest
{

	/**
	 * One algorithm with a requested key length in bits
	 *
	 * @param algorithm
	 *            the key generator algorithm
	 * @param keyLength
	 *            the requested key length in bits
	 * @param expectedEncodedBytes
	 *            the expected length of the encoded key in bytes
	 */
	record KeyLengthCase(String algorithm, int keyLength, int expectedEncodedBytes) {
	}

	static Stream<KeyLengthCase> keyLengthCases()
	{
		return Stream.of(new KeyLengthCase("AES", 128, 16), new KeyLengthCase("AES", 192, 24),
			new KeyLengthCase("AES", 256, 32), new KeyLengthCase("HmacSHA256", 512, 64),
			new KeyLengthCase("HmacSHA256", 128, 16), new KeyLengthCase("DESede", 168, 24));
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKey(String, int)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws NoSuchAlgorithmException
	 *             if the algorithm is not available
	 */
	@ParameterizedTest
	@MethodSource("keyLengthCases")
	void newSecretKeyHonoursRequestedLength(final KeyLengthCase testCase)
		throws NoSuchAlgorithmException
	{
		SecretKey first = SecretKeyFactoryExtensions.newSecretKey(testCase.algorithm(),
			testCase.keyLength());
		SecretKey second = SecretKeyFactoryExtensions.newSecretKey(testCase.algorithm(),
			testCase.keyLength());

		assertEquals(testCase.algorithm(), first.getAlgorithm());
		assertEquals(testCase.expectedEncodedBytes(), first.getEncoded().length,
			testCase.toString());
		assertEquals(testCase.expectedEncodedBytes(), second.getEncoded().length,
			testCase.toString());
		assertFalse(Arrays.equals(first.getEncoded(), second.getEncoded()),
			"keys must be freshly generated");
	}
}
