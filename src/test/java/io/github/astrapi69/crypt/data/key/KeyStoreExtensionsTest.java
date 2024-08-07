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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeySize;
import io.github.astrapi69.crypt.api.type.KeystoreType;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.factory.KeyStoreFactory;
import io.github.astrapi69.crypt.data.key.reader.CertificateReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link KeyStoreExtensions}
 */
public class KeyStoreExtensionsTest
{

	String alias = "alias-for-delete";
	/** The certificate for tests */
	X509Certificate certificate;
	File derDir;
	File keystoreFile;

	String newAlias = "new-alias";
	String password = "foobar-secret-pw";

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@BeforeEach
	protected void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		if (certificate == null)
		{
			final File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
			final File certificatePemFile = new File(pemDir, "certificate.pem");
			certificate = CertificateReader.readPemCertificate(certificatePemFile);
			assertNotNull(certificate);

		}

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		keystoreFile = new File(derDir, "keystore.jks");
		KeyStore keyStore = KeyStoreFactory.newKeyStore(keystoreFile, KeystoreType.JKS.name(),
			password);
		assertNotNull(keyStore);
		assertFalse(keyStore.containsAlias(alias));
		keyStore.setCertificateEntry(alias, certificate);

		assertTrue(keyStore.containsAlias(alias));
		keyStore.store(new FileOutputStream(keystoreFile), password.toCharArray());
	}

	/**
	 * Tear down method will be invoked after every unit test method
	 */
	@AfterEach
	protected void tearDown()
	{
		keystoreFile.delete();
	}

	/**
	 * Test method for {@link KeyStoreExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyStoreExtensions.class);
	}

	/**
	 * Test method for
	 * {@link KeyStoreExtensions#addAndStoreCertificate(KeyStore, File, String, String, Certificate)}
	 */
	@Test
	public void testAddAndStoreCertificate() throws Exception
	{
		Certificate actual;
		Certificate expected;
		PrivateKey privateKey;
		KeyPair keyPair;
		Certificate certificate;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		privateKey = keyPair.getPrivate();

		keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), password);

		certificate = TestObjectFactory.newCertificateForTests(privateKey);

		alias = newAlias;

		KeyStoreExtensions.addAndStoreCertificate(keyStore, keystoreFile, password, alias,
			certificate);
		// load again keystore from file
		keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), password);
		actual = keyStore.getCertificate(alias);
		assertNotNull(actual);
		expected = certificate;
		assertEquals(actual, expected);
	}

	/**
	 * Test method for
	 * {@link KeyStoreExtensions#addAndStorePrivateKey(KeyStore, File, String, PrivateKey, char[], Certificate[])}
	 */
	@Test
	public void testAddAndStorePrivateKey() throws Exception
	{
		PrivateKey actual;
		PrivateKey expected;
		KeyPair keyPair;
		Certificate certificate;
		Certificate[] certificateChain;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		expected = keyPair.getPrivate();

		keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), password);

		certificate = TestObjectFactory.newCertificateForTests(expected);
		certificateChain = ArrayFactory.newArray(certificate);

		alias = "test-pk";

		KeyStoreExtensions.addAndStorePrivateKey(keyStore, keystoreFile, alias, expected,
			password.toCharArray(), certificateChain);
		// load again keystore from file
		keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), password);

		actual = (PrivateKey)keyStore.getKey(alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);

		actual = KeyStoreExtensions.getPrivateKey(keyStore, alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);

		Certificate certificate1 = keyStore.getCertificate(alias);
		assertEquals(certificate, certificate1);
	}

	/**
	 * Test method for {@link KeyStoreExtensions#addCertificate(KeyStore, String, Certificate)}
	 */
	@Test
	public void testAddCertificate() throws Exception
	{
		Certificate actual;
		Certificate expected;
		PrivateKey privateKey;
		KeyPair keyPair;
		Certificate certificate;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		privateKey = keyPair.getPrivate();

		keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), password);

		certificate = TestObjectFactory.newCertificateForTests(privateKey);

		alias = newAlias;

		KeyStoreExtensions.addCertificate(keyStore, alias, certificate);

		actual = keyStore.getCertificate(alias);
		assertNotNull(actual);
		expected = certificate;
		assertEquals(actual, expected);
	}

	/**
	 * Test method for
	 * {@link KeyStoreExtensions#addPrivateKey(KeyStore, String, PrivateKey, char[], Certificate[])}
	 */
	@Test
	public void testAddPrivateKey() throws Exception
	{
		PrivateKey actual;
		PrivateKey expected;
		KeyPair keyPair;
		Certificate certificate;
		Certificate[] certificateChain;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		expected = keyPair.getPrivate();

		keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), password);

		certificate = TestObjectFactory.newCertificateForTests(expected);
		certificateChain = ArrayFactory.newArray(certificate);

		alias = "test-pk";

		KeyStoreExtensions.addPrivateKey(keyStore, alias, expected, password.toCharArray(),
			certificateChain);

		actual = (PrivateKey)keyStore.getKey(alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);

		actual = KeyStoreExtensions.getPrivateKey(keyStore, alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);

		Certificate certificate1 = keyStore.getCertificate(alias);
		assertEquals(certificate, certificate1);
	}

	/**
	 * Test method for {@link KeyStoreExtensions#deleteAlias(File, String, String)}
	 */
	@Test
	public void testDeleteAlias() throws Exception
	{
		KeyStore keyStore;
		boolean containsAlias;

		KeyStoreExtensions.deleteAlias(keystoreFile, alias, password);

		keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), password);
		containsAlias = keyStore.containsAlias(alias);

		assertFalse(containsAlias);
	}

	/**
	 * Test method for {@link KeyStoreExtensions#getCertificate(KeyStore, String)}
	 */
	@Test
	public void testGetCertificate() throws Exception
	{
		Certificate actual;
		Certificate expected;
		PrivateKey privateKey;
		KeyPair keyPair;
		Certificate certificate;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		privateKey = keyPair.getPrivate();

		keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), password);

		certificate = TestObjectFactory.newCertificateForTests(privateKey);

		alias = newAlias;

		KeyStoreExtensions.addCertificate(keyStore, alias, certificate);

		actual = KeyStoreExtensions.getCertificate(keyStore, alias);
		assertNotNull(actual);
		expected = certificate;
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link KeyStoreExtensions#getPrivateKey(KeyStore, String, char[])}
	 */
	@Test
	public void testGetPrivateKey() throws Exception
	{
		PrivateKey actual;
		PrivateKey expected;
		KeyPair keyPair;
		Certificate certificate;
		Certificate[] certificateChain;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		expected = keyPair.getPrivate();

		keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), password);

		certificate = TestObjectFactory.newCertificateForTests(expected);
		certificateChain = ArrayFactory.newArray(certificate);

		alias = "test-pk";

		KeyStoreExtensions.addPrivateKey(keyStore, alias, expected, password.toCharArray(),
			certificateChain);

		actual = (PrivateKey)keyStore.getKey(alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);

		actual = KeyStoreExtensions.getPrivateKey(keyStore, alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for
	 * {@link KeyStoreExtensions#setKeyEntry(KeyStore, String, Key, char[], Certificate[])}
	 */
	@Test
	public void testSetKeyEntry() throws Exception
	{
		KeyPair keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA,
			KeySize.KEYSIZE_2048);
		PrivateKey privateKey = keyPair.getPrivate();
		KeyStore keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(),
			password);

		Certificate certificate = TestObjectFactory.newCertificateForTests(privateKey);
		Certificate[] certificateChain = ArrayFactory.newArray(certificate);
		String alias = "set-key-entry-alias";

		KeyStoreExtensions.setKeyEntry(keyStore, alias, privateKey, password.toCharArray(),
			certificateChain);

		Key actualKey = keyStore.getKey(alias, password.toCharArray());
		assertNotNull(actualKey);
		assertEquals(privateKey, actualKey);

		Certificate actualCertificate = keyStore.getCertificate(alias);
		assertNotNull(actualCertificate);
		assertEquals(certificate, actualCertificate);
	}
}
