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
package io.github.astrapi69.crypt.data.key.reader;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

/**
 * The parameterized unit test class for the class {@link PrivateKeyReader}
 */
public class PrivateKeyReaderParameterizedTest
{
	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}
	 *
	 * @param filePath
	 *            the file path
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/privateKeyFiles.csv", numLinesToSkip = 1)
	public void testReadPrivateKey(String filePath) throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		File file = new File(filePath);
		PrivateKey actual = PrivateKeyReader.readPrivateKey(file);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)} with invalid file path
	 *
	 * @param filePath
	 *            the file path
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/invalidPrivateKeyFiles.csv", numLinesToSkip = 1)
	public void testReadPrivateKeyInvalidFile(String filePath)
	{
		File file = new File(filePath);
		assertThrows(IOException.class, () -> {
			PrivateKeyReader.readPrivateKey(file);
		});
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(byte[], String)} with invalid byte
	 * array and algorithm
	 *
	 * @param keyBytes
	 *            the byte array containing the private key bytes
	 * @param algorithm
	 *            the algorithm
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/invalidPrivateKeyBytes.csv", numLinesToSkip = 1)
	public void testReadPrivateKeyInvalidBytes(String keyBytes, String algorithm)
	{
		byte[] bytes = keyBytes.getBytes();
		assertThrows(NoSuchAlgorithmException.class, () -> {
			PrivateKeyReader.readPrivateKey(bytes, algorithm);
		});
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(byte[], String)} with empty byte array
	 *
	 * @param algorithm
	 *            the algorithm
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/emptyPrivateKeyBytes.csv", numLinesToSkip = 1)
	public void testReadPrivateKeyEmptyBytes(String algorithm)
	{
		byte[] emptyKeyBytes = new byte[0];
		assertThrows(NoSuchAlgorithmException.class, () -> {
			PrivateKeyReader.readPrivateKey(emptyKeyBytes, algorithm);
		});
	}
}
