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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;

/**
 * The unit test class for the class {@link HashExtensions}
 */
public class HashExtensionsParameterizedTest
{

	/**
	 * Parameterized test method for
	 * {@link HashExtensions#hash(String, String, HashAlgorithm, Charset)}
	 *
	 * @param password
	 *            the password to hash
	 * @param salt
	 *            the salt to use
	 * @param hashAlgorithm
	 *            the hash algorithm
	 * @param charset
	 *            the charset
	 * @param expected
	 *            the expected result
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/hash-test-data.csv", numLinesToSkip = 1)
	public void parameterizedTestHash(String password, String salt, String hashAlgorithm,
		String charset, String expected) throws NoSuchAlgorithmException
	{
		String actual = HashExtensions.hash(password, salt, HashAlgorithm.valueOf(hashAlgorithm),
			Charset.forName(charset));
		assertTrue(expected.equals(actual));
	}

	/**
	 * Parameterized test method for
	 * {@link HashExtensions#hashAndBase64(String, String, HashAlgorithm, Charset)}
	 *
	 * @param password
	 *            the password to hash
	 * @param salt
	 *            the salt to use
	 * @param hashAlgorithm
	 *            the hash algorithm
	 * @param charset
	 *            the charset
	 * @param expected
	 *            the expected result
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/hash-and-base64-test-data.csv", numLinesToSkip = 1)
	public void parameterizedTestHashAndBase64(String password, String salt, String hashAlgorithm,
		String charset, String expected) throws NoSuchAlgorithmException
	{
		String actual = HashExtensions.hashAndBase64(password, salt,
			HashAlgorithm.valueOf(hashAlgorithm), Charset.forName(charset));
		assertTrue(expected.equals(actual));
	}
}
