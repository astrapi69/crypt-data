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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.model.KeyInfo;
import io.github.astrapi69.crypt.data.model.KeyStoreInfo;
import io.github.astrapi69.file.create.model.FileInfo;

/**
 * Tests that both {@code newKeystoreAndSaveForSsl} overloads of {@link KeyStoreFactory} return the
 * keystore they stored and that it really holds the key entry
 */
class KeyStoreFactorySslKeyStoreTest
{

	private static final char[] PASSWORD = "password".toCharArray();
	private static final String ALIAS = "serverKey";

	private static KeyPair keyPair;
	private static X509Certificate certificate;

	@TempDir
	Path tempDir;

	@BeforeAll
	static void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		keyPair = generator.generateKeyPair();
		X500Name name = new X500Name("CN=Test Server");
		certificate = CertFactory.newX509CertificateV3(keyPair, name, 1, name, "SHA256withRSA");
	}

	private KeyStoreInfo newKeyStoreInfo(final String fileName)
	{
		File keystoreFile = new File(tempDir.toFile(), fileName);
		return KeyStoreInfo.builder().fileInfo(FileInfo.toFileInfo(keystoreFile)).type("JKS")
			.keystorePassword(PASSWORD).build();
	}

	private static void assertHoldsKeyEntry(final KeyStore keyStore) throws Exception
	{
		assertNotNull(keyStore, "the stored keystore must be returned");
		assertTrue(keyStore.containsAlias(ALIAS));
		assertTrue(keyStore.isKeyEntry(ALIAS));
		assertArrayEquals(keyPair.getPrivate().getEncoded(),
			keyStore.getKey(ALIAS, PASSWORD).getEncoded());
		assertEquals(certificate, keyStore.getCertificate(ALIAS));
	}

	private static void assertPersisted(final KeyStoreInfo keyStoreInfo) throws Exception
	{
		File keystoreFile = FileInfo.toFile(keyStoreInfo.getFileInfo());
		assertTrue(keystoreFile.isFile(), "keystore must be written to disk");
		KeyStore reloaded = KeyStore.getInstance("JKS");
		try (InputStream inputStream = new FileInputStream(keystoreFile))
		{
			reloaded.load(inputStream, PASSWORD);
		}
		assertHoldsKeyEntry(reloaded);
	}

	/**
	 * Test method for
	 * {@link KeyStoreFactory#newKeystoreAndSaveForSsl(KeyStoreInfo, java.security.PrivateKey, java.security.cert.Certificate, String, char[])}
	 *
	 * @throws Exception
	 *             if the keystore cannot be created
	 */
	@Test
	void newKeystoreAndSaveForSslWithKeyObjects() throws Exception
	{
		KeyStoreInfo keyStoreInfo = newKeyStoreInfo("objects.jks");

		KeyStore keyStore = KeyStoreFactory.newKeystoreAndSaveForSsl(keyStoreInfo,
			keyPair.getPrivate(), certificate, ALIAS, PASSWORD);

		assertHoldsKeyEntry(keyStore);
		assertPersisted(keyStoreInfo);
	}

	/**
	 * Test method for
	 * {@link KeyStoreFactory#newKeystoreAndSaveForSsl(KeyStoreInfo, KeyInfo, KeyInfo, String, char[])}
	 *
	 * @throws Exception
	 *             if the keystore cannot be created
	 */
	@Test
	void newKeystoreAndSaveForSslWithKeyModels() throws Exception
	{
		KeyStoreInfo keyStoreInfo = newKeyStoreInfo("models.jks");
		KeyInfo privateKeyModel = KeyInfo.builder().keyType(KeyType.PRIVATE_KEY.getDisplayValue())
			.encoded(keyPair.getPrivate().getEncoded())
			.algorithm(keyPair.getPrivate().getAlgorithm()).build();
		KeyInfo certificateModel = KeyInfo.builder().keyType(KeyType.CERTIFICATE.getDisplayValue())
			.encoded(certificate.getEncoded()).algorithm(certificate.getSigAlgName()).build();

		KeyStore keyStore = KeyStoreFactory.newKeystoreAndSaveForSsl(keyStoreInfo, privateKeyModel,
			certificateModel, ALIAS, PASSWORD);

		assertHoldsKeyEntry(keyStore);
		assertPersisted(keyStoreInfo);
	}
}
