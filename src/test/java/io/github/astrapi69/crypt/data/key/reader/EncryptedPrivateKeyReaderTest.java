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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Optional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link EncryptedPrivateKeyReader}
 */
public class EncryptedPrivateKeyReaderTest
{
	File derDir;
	File pwProtectedPrivateKeyFileRSA;
	File pwProtectedPrivateKeyFileDSA;
	File pwProtectedPrivateKeyFileEC;
	File pwProtectedPrivateKeyFileDH;
	File pwProtectedPrivateKeyFilePSS;

	String passwordRSA;
	String passwordDSA;
	String passwordEC;
	String passwordDH;
	String passwordPSS;
	PrivateKey pwProtectedPrivateKey;

	File pemDir;
	File encryptedPemFile;
	File nonEncryptedPemFile;
	String password;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             the exception
	 */
	@BeforeEach
	protected void setUp() throws Exception
	{
		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		pwProtectedPrivateKeyFileRSA = new File(derDir, "test-key-rsa.der");
		pwProtectedPrivateKeyFileDSA = new File(derDir, "test-key-dsa.der");
		pwProtectedPrivateKeyFileEC = new File(derDir, "test-key-ec.der");
		pwProtectedPrivateKeyFileDH = new File(derDir, "test-key-dh.der");
		pwProtectedPrivateKeyFilePSS = new File(derDir, "test-key-pss.der");

		passwordRSA = "secret";
		passwordDSA = "password123";
		passwordEC = "myPassword";
		passwordDH = "dhPassword";
		passwordPSS = "pssPassword";

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		encryptedPemFile = new File(pemDir, "encrypted-key.pem");
		nonEncryptedPemFile = new File(pemDir, "non-encrypted-key.pem");
		password = "password";
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#getKeyPair(File, String)} with encrypted PEM
	 * file
	 *
	 * @throws FileNotFoundException
	 *             is thrown if the file did not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws PEMException
	 *             is thrown if an error occurs on read the pem file
	 */
	@Test
	public void testGetKeyPairWithEncryptedPEM() throws FileNotFoundException, IOException,
		PEMException, OperatorCreationException, PKCSException
	{
		Security.addProvider(new BouncyCastleProvider());
		KeyPair keyPair = EncryptedPrivateKeyReader.getKeyPair(encryptedPemFile, password);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#getKeyPair(File, String)} with non-encrypted
	 * PEM file
	 *
	 * @throws FileNotFoundException
	 *             is thrown if the file did not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws PEMException
	 *             is thrown if an error occurs on read the pem file
	 */
	@Test
	public void testGetKeyPairWithNonEncryptedPEM()
		throws FileNotFoundException, IOException, PEMException, PKCSException
	{
		Security.addProvider(new BouncyCastleProvider());
		assertThrows(PEMException.class,
			() -> EncryptedPrivateKeyReader.getKeyPair(nonEncryptedPemFile, password));
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#getPrivateKey(File, String)}
	 */
	@Test
	public void testGetPrivateKeyRSA() throws OperatorCreationException, PKCSException
	{
		Security.addProvider(new BouncyCastleProvider());
		Optional<PrivateKey> optionalPrivateKey = EncryptedPrivateKeyReader
			.getPrivateKey(pwProtectedPrivateKeyFileRSA, passwordRSA);
		assertTrue(optionalPrivateKey.isPresent());
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#getPrivateKey(File, String)}
	 */
	@Test
	public void testGetPrivateKeyDSA() throws OperatorCreationException, PKCSException
	{
		Security.addProvider(new BouncyCastleProvider());
		Optional<PrivateKey> optionalPrivateKey = EncryptedPrivateKeyReader
			.getPrivateKey(pwProtectedPrivateKeyFileDSA, passwordDSA);
		assertTrue(optionalPrivateKey.isPresent());
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#getPrivateKey(File, String)}
	 */
	@Test
	public void testGetPrivateKeyEC() throws OperatorCreationException, PKCSException
	{
		Security.addProvider(new BouncyCastleProvider());
		Optional<PrivateKey> optionalPrivateKey = EncryptedPrivateKeyReader
			.getPrivateKey(pwProtectedPrivateKeyFileEC, passwordEC);
		assertTrue(optionalPrivateKey.isPresent());
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#getPrivateKey(File, String)}
	 */
	@Test
	public void testGetPrivateKeyDH() throws OperatorCreationException, PKCSException
	{
		Security.addProvider(new BouncyCastleProvider());
		Optional<PrivateKey> optionalPrivateKey = EncryptedPrivateKeyReader
			.getPrivateKey(pwProtectedPrivateKeyFileDH, passwordDH);
		assertTrue(optionalPrivateKey.isPresent());
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#getPrivateKey(File, String)} with wrong
	 * algorithm
	 */
	@Test
	public void testGetPrivateKeyWithWrongAlgorithm()
		throws OperatorCreationException, PKCSException
	{
		Security.addProvider(new BouncyCastleProvider());
		File wrongFile = new File(derDir, "wrong-key-file.der");
		String wrongPassword = "wrong-password";
		Optional<PrivateKey> optionalPrivateKey = EncryptedPrivateKeyReader.getPrivateKey(wrongFile,
			wrongPassword);
		assertFalse(optionalPrivateKey.isPresent());
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
