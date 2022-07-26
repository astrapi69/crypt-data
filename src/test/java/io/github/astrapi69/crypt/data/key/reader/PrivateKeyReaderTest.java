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

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import io.github.astrapi69.crypt.data.key.reader.EncryptedPrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.crypto.algorithm.Algorithm;
import io.github.astrapi69.crypto.algorithm.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypto.key.KeyFileFormat;
import io.github.astrapi69.crypto.key.KeySize;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link PrivateKeyReader}
 */
public class PrivateKeyReaderTest
{

	PrivateKey actual;

	File derDir;
	File passwordProtectedPrivateKeyDerFile;
	File passwordProtectedPrivateKeyPemFile;
	File pemDir;

	File encryptedPrivateKeyFile;

	File privateKeyDerFile;
	File privateKeyPemFile;
	File privateKeyPemFile2;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privateKeyPemFile = new File(pemDir, "private.pem");
		privateKeyPemFile2 = new File(pemDir, "private2.pem");
		passwordProtectedPrivateKeyPemFile = new File(pemDir, "pwp-private-key-pw-is-secret.pem");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKeyDerFile = new File(derDir, "private.der");
		passwordProtectedPrivateKeyDerFile = new File(derDir, "pwp-private-key-pw-is-secret.der");


		encryptedPrivateKeyFile = new File(pemDir, "test.key");
	}


	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(Algorithm, KeySize)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testGetPrivateKey() throws IOException
	{

		Optional<PrivateKey> optionalPrivateKey;
		File privateKeyFile;
		PrivateKey privateKey;
		String algorithm;


		privateKeyFile = FileFactory.newFile(
			PathFinder.getRelativePath(PathFinder.getSrcTestResourcesDir(), "der", "type"),
			"dh-pk.der");

		optionalPrivateKey = PrivateKeyReader.getPrivateKey(privateKeyFile);
		assertTrue(optionalPrivateKey.isPresent());
		privateKey = optionalPrivateKey.get();
		algorithm = privateKey.getAlgorithm();
		assertEquals(algorithm, "DH");

		privateKeyFile = FileFactory.newFile(
			PathFinder.getRelativePath(PathFinder.getSrcTestResourcesDir(), "der", "type"),
			"dsa-pk.der");

		optionalPrivateKey = PrivateKeyReader.getPrivateKey(privateKeyFile);
		assertTrue(optionalPrivateKey.isPresent());
		privateKey = optionalPrivateKey.get();
		algorithm = privateKey.getAlgorithm();
		assertEquals(algorithm, "DSA");

		privateKeyFile = FileFactory.newFile(
			PathFinder.getRelativePath(PathFinder.getSrcTestResourcesDir(), "der", "type"),
			"ec-pk.der");

		optionalPrivateKey = PrivateKeyReader.getPrivateKey(privateKeyFile);
		assertTrue(optionalPrivateKey.isPresent());
		privateKey = optionalPrivateKey.get();
		algorithm = privateKey.getAlgorithm();
		assertEquals(algorithm, "EC");

		privateKeyFile = FileFactory.newFile(
			PathFinder.getRelativePath(PathFinder.getSrcTestResourcesDir(), "der", "type"),
			"rsa-pk.der");

		optionalPrivateKey = PrivateKeyReader.getPrivateKey(privateKeyFile);
		assertTrue(optionalPrivateKey.isPresent());
		privateKey = optionalPrivateKey.get();
		algorithm = privateKey.getAlgorithm();
		assertEquals(algorithm, "RSA");

		privateKeyFile = FileFactory.newFile(
			PathFinder.getRelativePath(PathFinder.getSrcTestResourcesDir(), "der", "type"),
			"rsassa_pss-pk.der");

		optionalPrivateKey = PrivateKeyReader.getPrivateKey(privateKeyFile);
		assertTrue(optionalPrivateKey.isPresent());
		privateKey = optionalPrivateKey.get();
		algorithm = privateKey.getAlgorithm();
		assertEquals(algorithm, "RSASSA-PSS");
	}


	/**
	 * Test method for {@link PrivateKeyReader#getKeyFormat(File)}
	 */
	@Test
	public void testGetKeyFormat() throws IOException
	{
		KeyFileFormat actual;
		KeyFileFormat expected;

		actual = PrivateKeyReader.getKeyFormat(privateKeyDerFile);
		expected = KeyFileFormat.DER;
		assertEquals(actual, expected);

		actual = PrivateKeyReader.getKeyFormat(privateKeyPemFile);
		expected = KeyFileFormat.PEM;
		assertEquals(actual, expected);

		actual = PrivateKeyReader.getKeyFormat(privateKeyPemFile2);
		assertEquals(actual, expected);

		actual = PrivateKeyReader.getKeyFormat(encryptedPrivateKeyFile);
		expected = KeyFileFormat.UNKNOWN;
		assertEquals(actual, expected);

	}

	/**
	 * Test method for {@link PrivateKeyReader#isPemFormat(File)}
	 */
	@Test
	public void testIsPemFormat() throws Exception
	{
		boolean actual;
		// new scenario
		actual = PrivateKeyReader.isPemFormat(privateKeyDerFile);
		assertFalse(actual);

		// new scenario
		actual = PrivateKeyReader.isPemFormat(privateKeyPemFile);
		assertTrue(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#isPrivateKeyPasswordProtected(File)}
	 */
	@Test
	public void testIsPrivateKeyPasswordProtected() throws Exception
	{
		boolean actual;
		PrivateKey passwordProtectedPrivateKey;
		// new scenario
		actual = PrivateKeyReader.isPrivateKeyPasswordProtected(privateKeyDerFile);
		assertFalse(actual);
		// new scenario
		// check if the pk is pwp...
		passwordProtectedPrivateKey = EncryptedPrivateKeyReader
			.readPasswordProtectedPrivateKey(passwordProtectedPrivateKeyDerFile, "secret");

		assertNotNull(passwordProtectedPrivateKey);

		actual = PrivateKeyReader.isPrivateKeyPasswordProtected(passwordProtectedPrivateKeyDerFile);
		assertTrue(actual);

		// new scenario
		passwordProtectedPrivateKey = EncryptedPrivateKeyReader
			.readPasswordProtectedPrivateKey(passwordProtectedPrivateKeyPemFile, "secret");

		assertNotNull(passwordProtectedPrivateKey);

		actual = PrivateKeyReader.isPrivateKeyPasswordProtected(passwordProtectedPrivateKeyDerFile);
		assertTrue(actual);

		// new scenario
		actual = PrivateKeyReader.isPrivateKeyPasswordProtected(privateKeyPemFile);
		assertFalse(actual);
	}


	/**
	 * Test method for {@link PrivateKeyReader#validatePrivateKey(File)}
	 */
	@Test
	public void testValidatePrivateKey() throws Exception
	{
		boolean actual;
		PrivateKey passwordProtectedPrivateKey;
		// new scenario
		actual = PrivateKeyReader.validatePrivateKey(privateKeyDerFile);
		assertTrue(actual);
		// new scenario
		// check if the pk is pwp...
		passwordProtectedPrivateKey = EncryptedPrivateKeyReader
			.readPasswordProtectedPrivateKey(passwordProtectedPrivateKeyDerFile, "secret");

		assertNotNull(passwordProtectedPrivateKey);

		actual = PrivateKeyReader.validatePrivateKey(passwordProtectedPrivateKeyDerFile);
		assertFalse(actual);

		// new scenario
		passwordProtectedPrivateKey = EncryptedPrivateKeyReader
			.readPasswordProtectedPrivateKey(passwordProtectedPrivateKeyPemFile, "secret");

		assertNotNull(passwordProtectedPrivateKey);

		actual = PrivateKeyReader.validatePrivateKey(passwordProtectedPrivateKeyDerFile);
		assertFalse(actual);

		// new scenario
		actual = PrivateKeyReader.validatePrivateKey(privateKeyPemFile);
		assertTrue(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPemFileAsBase64() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		String privateKeyAsBase64String;
		String base64;

		privateKeyAsBase64String = PrivateKeyReader.readPemFileAsBase64(privateKeyPemFile);

		actual = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		base64 = PrivateKeyExtensions.toBase64(actual);
		assertNotNull(privateKeyAsBase64String);
		assertNotNull(base64);

		privateKeyAsBase64String = PrivateKeyReader.readPemFileAsBase64(privateKeyPemFile2);

		actual = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		base64 = PrivateKeyExtensions.toBase64(actual);
		assertNotNull(privateKeyAsBase64String);
		assertNotNull(base64);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPemPrivateKey(File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPemPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		actual = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPemPrivateKey(File, String)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPemPrivateKeyFileString() throws NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException, IOException
	{
		actual = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile,
			KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPemPrivateKey(String, String)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred. *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPemPrivateKeyStringString() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		String privateKeyAsBase64String;

		privateKeyAsBase64String = PrivateKeyReader.readPemFileAsBase64(privateKeyPemFile);

		actual = PrivateKeyReader.readPemPrivateKey(privateKeyAsBase64String,
			KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPemPrivateKey(String)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred. *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPemPrivateKeyString() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		String privateKeyAsBase64String;
		privateKeyAsBase64String = PrivateKeyReader.readPemFileAsBase64(privateKeyPemFile);
		actual = PrivateKeyReader.readPemPrivateKey(privateKeyAsBase64String);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		actual = PrivateKeyReader.readPrivateKey(privateKeyDerFile);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPrivateKeyFromByteArray() throws NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException, IOException
	{
		actual = PrivateKeyReader.readPrivateKey(Files.readAllBytes(privateKeyDerFile.toPath()));
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPrivateKeyFromFileWithAlgorithm() throws NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException, IOException
	{
		actual = PrivateKeyReader.readPrivateKey(privateKeyDerFile,
			KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(PrivateKeyReader.class);
	}

}
