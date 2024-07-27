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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.spec.KeySpec;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * The parameterized test class for the class {@link KeySpecFactory}
 */
public class KeySpecFactoryParameterizedTest
{

	/**
	 * Parameterized test method for {@link KeySpecFactory#newPBEKeySpec(String)}
	 *
	 * @param privateKey
	 *            the private key
	 */
	@ParameterizedTest
	@CsvSource({ "password1", "password2", "password3" })
	public void testNewPBEKeySpecString(String privateKey)
	{
		KeySpec actual = KeySpecFactory.newPBEKeySpec(privateKey);
		assertNotNull(actual);
	}

	/**
	 * Parameterized test method for {@link KeySpecFactory#newPBEKeySpec(String, byte[], int)}
	 *
	 * @param password
	 *            the password
	 * @param saltHex
	 *            the salt
	 * @param iterationCount
	 *            the iteration count
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/pbekeyspec_data.csv", numLinesToSkip = 1)
	public void testNewPBEKeySpecStringByteArrayInt(String password, String saltHex,
		int iterationCount)
	{
		byte[] salt = javax.xml.bind.DatatypeConverter.parseHexBinary(saltHex);
		KeySpec actual = KeySpecFactory.newPBEKeySpec(password, salt, iterationCount);
		assertNotNull(actual);
	}

	/**
	 * Parameterized test method for {@link KeySpecFactory#newSecretKeySpec(byte[], String)}
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param key
	 *            the key
	 */
	@ParameterizedTest
	@CsvSource({ "AES, 1234567890123456", "AES, abcdefghijklmnop" })
	public void testNewSecretKeySpecByteArrayString(String algorithm, String key)
	{
		SecretKeySpec secretKeySpec = KeySpecFactory.newSecretKeySpec(key.getBytes(), algorithm);
		assertNotNull(secretKeySpec);
	}

	/**
	 * Parameterized test method for {@link KeySpecFactory#newSecretKeySpec(String, int)}
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keyLength
	 *            the key length
	 */
	@ParameterizedTest
	@CsvSource({ "AES, 128", "AES, 192", "AES, 256" })
	public void testNewSecretKeySpecStringInt(String algorithm, int keyLength) throws Exception
	{
		SecretKeySpec secretKeySpec = KeySpecFactory.newSecretKeySpec(algorithm, keyLength);
		assertNotNull(secretKeySpec);
	}

}
