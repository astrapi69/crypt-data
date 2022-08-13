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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypto.algorithm.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.file.read.ReadFileExtensions;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link EncryptedPrivateKeyReader}
 */
public class EncryptedPrivateKeyReaderTest
{
	File derDir;
	File encryptedPrivateKeyFile;
	File pwProtectedPrivateKeyFile;

	String password;
	File pemDir;
	PrivateKey pwProtectedPrivateKey;

	/**
	 * Sets up method will be invoked before every unit test method in this class.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@BeforeEach
	protected void setUp() throws Exception
	{
		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		encryptedPrivateKeyFile = new File(pemDir, "test.key");
		pwProtectedPrivateKeyFile = new File(derDir, "pwp-private-key-pw-is-secret.der");
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#getKeyPair(File, String)}
	 * 
	 * @throws FileNotFoundException
	 *             is thrown if the file did not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws PEMException
	 *             is thrown if an error occurs on read the pem file
	 */
	@Test
	public void testGetKeyPair() throws FileNotFoundException, PEMException, IOException
	{
		Security.addProvider(new BouncyCastleProvider());
		password = "bosco";
		KeyPair keyPair = EncryptedPrivateKeyReader.getKeyPair(encryptedPrivateKeyFile, password);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyReader#readPasswordProtectedPrivateKey(byte[], String, String)}
	 */
	@Test
	public void testReadPasswordProtectedPrivateKeyByteArrayStringString()
		throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException,
		NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException
	{
		password = "secret";
		byte[] bytes = ReadFileExtensions.readFileToBytearray(pwProtectedPrivateKeyFile);
		pwProtectedPrivateKey = EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(bytes,
			password, KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		assertNotNull(pwProtectedPrivateKey);
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyReader#readPasswordProtectedPrivateKey(File, String)}
	 */
	@Test
	public void testReadPasswordProtectedPrivateKeyFileString()
		throws InvalidAlgorithmParameterException, NoSuchPaddingException, IOException,
		NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException
	{
		password = "secret";
		pwProtectedPrivateKey = EncryptedPrivateKeyReader
			.readPasswordProtectedPrivateKey(pwProtectedPrivateKeyFile, password);
		assertNotNull(pwProtectedPrivateKey);
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyReader#readPasswordProtectedPrivateKey(File, String, String)}
	 */
	@Test
	public void testReadPasswordProtectedPrivateKeyFileStringString()
		throws InvalidAlgorithmParameterException, NoSuchPaddingException, IOException,
		NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException
	{
		password = "secret";
		pwProtectedPrivateKey = EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(
			pwProtectedPrivateKeyFile, password, KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		assertNotNull(pwProtectedPrivateKey);
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(EncryptedPrivateKeyReader.class);
	}

}
