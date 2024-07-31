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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeySize;
import io.github.astrapi69.crypt.api.type.KeystoreType;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.factory.KeyStoreFactory;
import io.github.astrapi69.crypt.data.key.reader.CertificateReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The parameterized unit test class for the class {@link KeyStoreExtensions}
 */
public class KeyStoreExtensionsParameterizedTest
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
		keyStore.setCertificateEntry(alias, certificate);
		keyStore.store(new FileOutputStream(keystoreFile), password.toCharArray());
	}

	/**
	 * Parameterized test method for
	 * {@link KeyStoreExtensions#addAndStoreCertificate(KeyStore, File, String, String, Certificate)}
	 *
	 * @param alias
	 *            the alias
	 * @param certificateFileName
	 *            the certificate file name
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/keystoreExtensionsTest.csv", numLinesToSkip = 1)
	public void testAddAndStoreCertificateParameterized(String alias, String certificateFileName)
		throws Exception
	{
		Certificate actual;
		Certificate expected;
		PrivateKey privateKey;
		KeyPair keyPair;
		Certificate certificate;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		privateKey = keyPair.getPrivate();

		keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), password);

		File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		File certificatePemFile = new File(pemDir, certificateFileName);
		certificate = CertificateReader.readPemCertificate(certificatePemFile);

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
	 * Parameterized test method for
	 * {@link KeyStoreExtensions#addAndStorePrivateKey(KeyStore, File, String, PrivateKey, char[], Certificate[])}
	 *
	 * @param alias
	 *            the alias
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/keystoreExtensionsTest.csv", numLinesToSkip = 1)
	public void testAddAndStorePrivateKeyParameterized(String alias) throws Exception
	{
		PrivateKey actual;
		PrivateKey expected;
		KeyPair keyPair;
		Certificate certificate;
		Certificate[] certificateChain;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		expected = keyPair.getPrivate();

		keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), password);

		certificate = TestObjectFactory.newCertificateForTests(expected);
		certificateChain = ArrayFactory.newArray(certificate);

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
}
