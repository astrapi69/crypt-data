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
package io.github.astrapi69.crypt.data.model;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.key.KeyExtensions;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.create.FileInfo;

/**
 * Unit test for {@link KeystoreCreator}.
 */
public class KeystoreCreatorTest
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
			.keyPairInfo(keyPairInfo).issuer(distinguishedNameInfo)
			.serial(new BigInteger(160, new SecureRandom()))
			.validity(Validity.builder().notBefore(ZonedDateTime.parse("2023-12-01T00:00:00Z"))
				.notAfter(ZonedDateTime.parse("2025-01-01T00:00:00Z")).build())
			.subject(distinguishedNameInfo).signatureAlgorithm("SHA256withRSA").build();

		X509CertificateV3Info x509CertificateV3Info = X509CertificateV3Info.builder()
			.certificateV1Info(x509CertificateV1Info).extensions(extensionInfos).build();

		certificate = CertFactory.newX509CertificateV3(x509CertificateV3Info);
	}

	/**
	 * Test for
	 * {@link KeystoreCreator#newKeystoreAndSaveForSsl(KeyStoreInfo, KeyInfo, KeyInfo, String, char[])}.
	 */
	@Test
	public void testNewKeystoreAndSaveForSsl() throws Exception
	{
		String base64 = KeyExtensions.toBase64(certificate.getEncoded());
		System.out.println(base64);

		KeyInfo privateKeyModel = KeyInfo.builder().keyType(KeyType.PRIVATE_KEY.getDisplayValue())
			.encoded(keyPair.getPrivate().getEncoded())
			.algorithm(keyPair.getPrivate().getAlgorithm()).build();

		KeyInfo publicKeyModel = KeyInfo.builder().keyType(KeyType.PUBLIC_KEY.getDisplayValue())
			.encoded(keyPair.getPublic().getEncoded()).algorithm(keyPair.getPublic().getAlgorithm())
			.build();

		KeyInfo certificateModel = KeyInfo.builder().keyType(KeyType.CERTIFICATE.getDisplayValue())
			.encoded(certificate.getEncoded()).algorithm(certificate.getSigAlgName()).build();

		KeystoreCreator.newKeystoreAndSaveForSsl(keyStoreInfo, privateKeyModel, certificateModel,
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
}
