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
package io.github.astrapi69.crypt.data.hash;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;

/**
 * Parameterized test for {@link HashExtensions#hash(byte[], String, HashAlgorithm, Charset)}: the
 * result must be the digest of {@code salt-bytes || input}, and both the salt and the input must
 * actually reach the digest
 */
class HashExtensionsSaltParameterizedTest
{

	/**
	 * One salted hash computation
	 *
	 * @param description
	 *            what the case covers
	 * @param input
	 *            the bytes to hash
	 * @param salt
	 *            the salt or null for no salt
	 * @param algorithm
	 *            the hash algorithm
	 * @param charset
	 *            the charset used to encode the salt
	 */
	record SaltedHashCase(String description, byte[] input, String salt, HashAlgorithm algorithm,
		Charset charset) {
	}

	static Stream<SaltedHashCase> saltedHashCases()
	{
		byte[] input = "the quick brown fox".getBytes(StandardCharsets.UTF_8);
		return Stream.of(
			new SaltedHashCase("sha-256 with salt", input, "s4lt", HashAlgorithm.SHA_256,
				StandardCharsets.UTF_8),
			new SaltedHashCase("sha-512 with non-ascii salt", input, "Sälz", HashAlgorithm.SHA_512,
				StandardCharsets.UTF_8),
			new SaltedHashCase("sha-1 with latin-1 salt", input, "Sälz", HashAlgorithm.SHA_1,
				StandardCharsets.ISO_8859_1),
			new SaltedHashCase("sha-256 without salt", input, null, HashAlgorithm.SHA_256,
				StandardCharsets.UTF_8),
			new SaltedHashCase("empty input with salt", new byte[0], "only-salt",
				HashAlgorithm.SHA_256, StandardCharsets.UTF_8));
	}

	private static byte[] referenceDigest(final SaltedHashCase testCase)
		throws NoSuchAlgorithmException
	{
		MessageDigest digest = MessageDigest.getInstance(testCase.algorithm().getAlgorithm());
		if (testCase.salt() != null)
		{
			digest.update(testCase.salt().getBytes(testCase.charset()));
		}
		return digest.digest(testCase.input());
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], String, HashAlgorithm, Charset)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws NoSuchAlgorithmException
	 *             if the algorithm is not available
	 */
	@ParameterizedTest
	@MethodSource("saltedHashCases")
	void hashIsDigestOfSaltAndInput(final SaltedHashCase testCase) throws NoSuchAlgorithmException
	{
		byte[] actual = HashExtensions.hash(testCase.input(), testCase.salt(), testCase.algorithm(),
			testCase.charset());

		assertArrayEquals(referenceDigest(testCase), actual, testCase.description());
		// deterministic
		assertArrayEquals(actual, HashExtensions.hash(testCase.input(), testCase.salt(),
			testCase.algorithm(), testCase.charset()), testCase.description());
		// the input must reach the digest: a different input changes the result
		byte[] otherInput = Arrays.copyOf(testCase.input(), testCase.input().length + 1);
		assertFalse(Arrays.equals(actual, HashExtensions.hash(otherInput, testCase.salt(),
			testCase.algorithm(), testCase.charset())), testCase.description());
		// the salt must reach the digest: a different salt changes the result
		String otherSalt = testCase.salt() == null ? "x" : testCase.salt() + "x";
		assertFalse(Arrays.equals(actual, HashExtensions.hash(testCase.input(), otherSalt,
			testCase.algorithm(), testCase.charset())), testCase.description());
	}
}
