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
package io.github.astrapi69.crypto.key.writer;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.meanbean.test.BeanTester;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.crypto.algorithm.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypto.key.reader.EncryptedPrivateKeyReader;
import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import io.github.astrapi69.delete.DeleteFileExtensions;
import io.github.astrapi69.search.PathFinder;

/**
 * The unit test class for the class {@link EncryptedPrivateKeyWriter}.
 */
public class EncryptedPrivateKeyWriterTest
{
	PrivateKey actual;
	File derDir;

	File encryptedPrivateKeyFile;
	PrivateKey expected;
	String password;
	PrivateKey readedPrivateKey;

	/**
	 * Sets up method will be invoked before every unit test method in this class.
	 */
	@BeforeMethod
	protected void setUp()
	{
		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		encryptedPrivateKeyFile = new File(derDir, "encryptedPrivate.der");
	}

	/**
	 * Tear down method will be invoked after every unit test method in this class.
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@AfterMethod
	protected void tearDown() throws IOException
	{
		if (encryptedPrivateKeyFile.exists())
		{
			DeleteFileExtensions.delete(encryptedPrivateKeyFile);
		}
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyWriter#encryptPrivateKeyWithPassword(PrivateKey, File, String)}
	 * 
	 * Test encrypt private key with password private key file string.
	 * 
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws IllegalBlockSizeException
	 *             the illegal block size exception
	 * @throws BadPaddingException
	 *             is thrown when a particular padding mechanism is expected for the input data but
	 *             the data is not padded properly.
	 * @throws InvalidParameterSpecException
	 *             the invalid parameter spec exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptPrivateKeyWithPasswordPrivateKeyFileString()
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
		IOException, InvalidKeyException, NoSuchPaddingException,
		InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
		InvalidParameterSpecException
	{
		PrivateKey readedPrivateKey;
		String password;
		PrivateKey decryptedPrivateKey;

		readedPrivateKey = PrivateKeyReader.readPrivateKey(PathFinder.getSrcTestResourcesDir(),
			"der", "private.der");
		password = "secret";

		EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(readedPrivateKey,
			encryptedPrivateKeyFile, password);

		decryptedPrivateKey = EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(
			encryptedPrivateKeyFile, password, KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		expected = readedPrivateKey;
		actual = decryptedPrivateKey;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyWriter#getPasswordProtectedPrivateKey(byte[], String)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails list.
	 * @throws IllegalBlockSizeException
	 *             is thrown when the length of data provided to a block cipher is incorrect, i.e.,
	 *             does not match the block size of the cipher.
	 * @throws BadPaddingException
	 *             is thrown when a particular padding mechanism is expected for the input data but
	 *             the data is not padded properly.
	 * @throws InvalidParameterSpecException
	 *             is thrown if the InvalidParameterSpec creation fails
	 */
	@Test
	public void testEncryptPrivateKeyWithPasswordPrivateKeyString() throws NoSuchAlgorithmException,
		InvalidKeySpecException, IOException, NoSuchProviderException,
		InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
		BadPaddingException, InvalidParameterSpecException, InvalidKeyException
	{
		PrivateKey readedPrivateKey;
		String password;
		readedPrivateKey = PrivateKeyReader.readPrivateKey(PathFinder.getSrcTestResourcesDir(),
			"der", "private.der");
		password = "secret";
		byte[] bytes = EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(readedPrivateKey,
			password);
		assertNotNull(bytes);

		PrivateKey passwordProtectedPrivateKey = EncryptedPrivateKeyWriter
			.getPasswordProtectedPrivateKey(bytes, password);
		assertNotNull(passwordProtectedPrivateKey);
		assertEquals(readedPrivateKey, passwordProtectedPrivateKey);
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyWriter} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(EncryptedPrivateKeyWriter.class);
	}

}
