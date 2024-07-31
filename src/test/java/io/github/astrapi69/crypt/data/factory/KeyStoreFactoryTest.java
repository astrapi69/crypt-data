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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.api.type.KeystoreType;
import io.github.astrapi69.crypt.data.key.KeyExtensions;
import io.github.astrapi69.crypt.data.model.DistinguishedNameInfo;
import io.github.astrapi69.crypt.data.model.ExtensionInfo;
import io.github.astrapi69.crypt.data.model.KeyInfo;
import io.github.astrapi69.crypt.data.model.KeyPairInfo;
import io.github.astrapi69.crypt.data.model.KeyStoreInfo;
import io.github.astrapi69.crypt.data.model.Validity;
import io.github.astrapi69.crypt.data.model.X509CertificateV1Info;
import io.github.astrapi69.crypt.data.model.X509CertificateV3Info;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.create.FileInfo;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link KeyStoreFactory}
 */
public class KeyStoreFactoryTest
{

	private DistinguishedNameInfo distinguishedNameInfo;
	private KeyPairInfo keyPairInfo;
	private KeyStoreInfo keyStoreInfo;
	private char[] password;
	private X509Certificate certificate;
	private KeyPair keyPair;

	@TempDir
	Path tempDir;

	@BeforeEach
	public void setUp() throws Exception
	{
		password = "password".toCharArray();
		Security.addProvider(new BouncyCastleProvider());

		File keystoreFile = FileFactory.newFile(tempDir.toFile(), "new-keystore.jks");
		distinguishedNameInfo = DistinguishedNameInfo.builder().commonName("Test Server")
			.countryCode("GB").location("London").organisation("My Company")
			.organisationUnit("IT Department").state("Greater London").build();

		keyPairInfo = KeyPairInfo.builder().algorithm("RSA").keySize(2048).build();
		FileInfo fileInfo = FileInfo.toFileInfo(keystoreFile);

		keyStoreInfo = KeyStoreInfo.builder().fileInfo(fileInfo).type("JKS")
			.keystorePassword(password).build();

		keyPair = KeyPairInfo.toKeyPair(keyPairInfo);
		ExtensionInfo[] extensionInfos = ArrayFactory.newArray(ExtensionInfo.builder()
			.extensionId("1.3.6.1.5.5.7.3.2").critical(false).value("foo bar").build());

		X509CertificateV1Info x509CertificateV1Info = X509CertificateV1Info.builder()
			.issuer(distinguishedNameInfo).serial(new BigInteger(160, new SecureRandom()))
			.validity(Validity.builder().notBefore(ZonedDateTime.parse("2023-12-01T00:00:00Z"))
				.notAfter(ZonedDateTime.parse("2025-01-01T00:00:00Z")).build())
			.subject(distinguishedNameInfo).signatureAlgorithm("SHA256withRSA").build();

		X509CertificateV3Info x509CertificateV3Info = X509CertificateV3Info.builder()
			.certificateV1Info(x509CertificateV1Info).extensions(extensionInfos).build();

		certificate = CertFactory.newX509CertificateV3(keyPair, x509CertificateV3Info);
	}

	/**
	 * Test for
	 * {@link KeyStoreFactory#newKeystoreAndSaveForSsl(KeyStoreInfo, KeyInfo, KeyInfo, String, char[])}
	 */
	@Test
	public void testNewKeystoreAndSaveForSsl() throws Exception
	{
		String base64 = KeyExtensions.toBase64(certificate.getEncoded());
		System.out.println(base64);

		KeyInfo privateKeyModel = KeyInfo.builder().keyType(KeyType.PRIVATE_KEY.getDisplayValue())
			.encoded(keyPair.getPrivate().getEncoded())
			.algorithm(keyPair.getPrivate().getAlgorithm()).build();

		KeyInfo certificateModel = KeyInfo.builder().keyType(KeyType.CERTIFICATE.getDisplayValue())
			.encoded(certificate.getEncoded()).algorithm(certificate.getSigAlgName()).build();

		KeyStoreFactory.newKeystoreAndSaveForSsl(keyStoreInfo, privateKeyModel, certificateModel,
			"serverKey", password);

		File keystoreFile = FileInfo.toFile(keyStoreInfo.getFileInfo());
		assertNotNull(keystoreFile);
		assertTrue(keystoreFile.exists());

		// Load the keystore and retrieve the private key
		KeyStore keyStore = KeyStore.getInstance(keyStoreInfo.getType());
		try (FileInputStream fis = new FileInputStream(keystoreFile))
		{
			keyStore.load(fis, keyStoreInfo.getKeystorePassword());
		}

		Key key = keyStore.getKey("serverKey", password);
		assertNotNull(key);
		assertTrue(key instanceof PrivateKey);

		PrivateKey retrievedPrivateKey = (PrivateKey)key;
		assertNotNull(retrievedPrivateKey);
		System.out.println("Retrieved Private Key: " + retrievedPrivateKey);
	}

	/**
	 * Test for
	 * {@link KeyStoreFactory#newKeystoreAndSaveForSsl(KeyStoreInfo, KeyInfo, KeyInfo, String, char[])}
	 */
	@Test
	public void testStoreAndRetrieveCertificateOnly() throws Exception
	{
		// Create a keystore and store only the certificate
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, password);
		keyStore.setCertificateEntry("certAlias", certificate);

		File keystoreFile = new File(tempDir.toFile(), "cert-only-keystore.jks");
		try (FileOutputStream fos = new FileOutputStream(keystoreFile))
		{
			keyStore.store(fos, password);
		}

		// Load the keystore and try to retrieve the private key
		KeyStore loadedKeyStore = KeyStore.getInstance("JKS");
		try (FileInputStream fis = new FileInputStream(keystoreFile))
		{
			loadedKeyStore.load(fis, password);
		}

		Key key = loadedKeyStore.getKey("certAlias", password);
		// This will be null because only the certificate was stored
		assertTrue(key == null);
	}

	/**
	 * Test method for {@link KeyStoreFactory#newKeyStore(File, String, String)} and
	 * {@link KeyStoreFactory#loadKeyStore(File, String, String)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             if the algorithm used to check the integrity of the keystore cannot be found
	 * @throws CertificateException
	 *             if any of the certificates in the keystore could not be loaded
	 * @throws FileNotFoundException
	 *             if the file not found
	 * @throws KeyStoreException
	 *             if the keystore has not been initialized (loaded)
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	@Test
	public void testNewKeyStore() throws NoSuchAlgorithmException, CertificateException,
		FileNotFoundException, KeyStoreException, IOException
	{
		File publickeyDerDir;
		File keystoreJksFile;
		KeyStore keystore;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		keystoreJksFile = new File(publickeyDerDir, "keystore.jks");

		keystore = KeyStoreFactory.newKeyStore(keystoreJksFile, KeystoreType.JKS.name(),
			"foobar-secret-pw");
		assertNotNull(keystore);

		keystore = KeyStoreFactory.loadKeyStore(keystoreJksFile, KeystoreType.JKS.name(),
			"foobar-secret-pw");
		assertNotNull(keystore);

		keystore = KeyStoreFactory.loadKeyStore(keystoreJksFile, KeystoreType.JKS.name(),
			"foobar-secret-pw");
		assertNotNull(keystore);
		FileUtils.deleteQuietly(keystoreJksFile);
	}

	/**
	 * Test method for {@link KeyStoreFactory#loadKeyStore(File, String, String)}
	 *
	 * @throws KeyStoreException
	 *             if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             if there is an error with a certificate
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	@Test
	public void testLoadKeyStore()
		throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException
	{
		File jksDir;
		File keystoreJksFile;
		KeyStore keystore;

		jksDir = new File(PathFinder.getSrcTestResourcesDir(), "jks");
		keystoreJksFile = new File(jksDir, "keystore.jks");

		keystore = KeyStoreFactory.loadKeyStore(keystoreJksFile, KeystoreType.JKS.name(),
			"keystore-pw");
		assertNotNull(keystore);
	}

	/**
	 * Test method for {@link KeyStoreFactory#loadKeyStore(File, String, String)}
	 *
	 * @throws KeyStoreException
	 *             if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             if there is an error with a certificate
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	@Test
	public void testLoadKeyStoreWithKeyStoreInfo()
		throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException
	{
		File jksDir;
		File keystoreJksFile;
		KeyStore keystore;
		KeyStoreInfo keyStoreInfo;

		jksDir = new File(PathFinder.getSrcTestResourcesDir(), "jks");
		keystoreJksFile = new File(jksDir, "keystore.jks");
		keyStoreInfo = KeyStoreInfo.builder().fileInfo(FileInfo.toFileInfo(keystoreJksFile))
			.type(KeystoreType.JKS.name()).keystorePassword("keystore-pw".toCharArray()).build();

		keystore = KeyStoreFactory.loadKeyStore(keyStoreInfo);
		assertNotNull(keystore);
	}

	/**
	 * Test method for {@link KeyStoreFactory} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyStoreFactory.class);
	}
}
