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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;
import org.meanbean.test.BeanVerifier;

import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.key.reader.CertificateReader;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.evaluate.object.evaluator.EqualsHashCodeAndToStringEvaluator;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link KeyInfo}
 */
public class KeyInfoTest
{
	File derDir;
	File pemDir;

	PrivateKey privateKey;
	File privateKeyDerFile;
	File privateKeyPemFile;
	PublicKey publicKey;
	File publicKeyPemFile;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException
	{
		Security.addProvider(new BouncyCastleProvider());

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privateKeyPemFile = new File(pemDir, "private.pem");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKeyDerFile = new File(derDir, "private.der");
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		publicKeyPemFile = new File(pemDir, "public.pem");
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);
	}

	/**
	 * Test method for {@link KeyInfo} constructors and builders
	 */
	@Test
	@DisplayName("Test KeyInfo constructors and builders")
	public final void testConstructors() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException, CertificateException
	{
		File keyFile;
		KeyInfo keyInfo;
		PrivateKey privateKeyFromInfo;
		PublicKey publicKeyFromInfo;
		X509Certificate certificate;
		X509Certificate certificateFromInfo;

		// Test with private key
		keyInfo = KeyInfo.builder().encoded(privateKey.getEncoded())
			.keyType(KeyType.PRIVATE_KEY.getDisplayValue()).algorithm(privateKey.getAlgorithm())
			.build();
		privateKeyFromInfo = PrivateKeyReader.readPrivateKey(keyInfo.getEncoded(),
			keyInfo.getAlgorithm());
		assertEquals(privateKey, privateKeyFromInfo);

		// Test with public key
		keyInfo = KeyInfo.builder().encoded(publicKey.getEncoded())
			.keyType(KeyType.PUBLIC_KEY.getDisplayValue()).algorithm(publicKey.getAlgorithm())
			.build();
		publicKeyFromInfo = PublicKeyReader.readPublicKey(keyInfo.getEncoded(),
			keyInfo.getAlgorithm());
		assertEquals(publicKey, publicKeyFromInfo);

		// Test with new private key file
		keyFile = new File(pemDir, "8192-ssh-key.pem");
		privateKey = PrivateKeyReader.readPemPrivateKey(keyFile);
		keyInfo = KeyInfo.builder().encoded(privateKey.getEncoded())
			.keyType(KeyType.PRIVATE_KEY.getDisplayValue()).algorithm(privateKey.getAlgorithm())
			.build();
		privateKeyFromInfo = PrivateKeyReader.readPrivateKey(keyInfo.getEncoded(),
			keyInfo.getAlgorithm());
		assertEquals(privateKey, privateKeyFromInfo);

		// Test with certificate
		keyFile = new File(pemDir, "certificate.pem");
		certificate = CertificateReader.readCertificate(keyFile);
		keyInfo = KeyInfo.builder().encoded(certificate.getEncoded())
			.keyType(KeyType.CERTIFICATE.getDisplayValue()).algorithm("").build();
		certificateFromInfo = CertificateReader.readCertificate(keyInfo.getEncoded());
		assertEquals(certificate, certificateFromInfo);
	}

	/**
	 * Test method for {@link KeyInfo#equals(Object)}, {@link KeyInfo#hashCode()} and
	 * {@link KeyInfo#toString()}
	 */
	@Test
	@DisplayName("Test KeyInfo equals, hashCode and toString methods")
	public void testEqualsHashcodeAndToStringWithClass() throws CertificateException, IOException
	{
		File keyFile;
		KeyInfo keyInfo;
		X509Certificate certificate;
		boolean expected;
		boolean actual;

		keyFile = new File(pemDir, "certificate.pem");
		certificate = CertificateReader.readCertificate(keyFile);
		keyInfo = KeyInfo.builder().encoded(certificate.getEncoded())
			.keyType(KeyType.CERTIFICATE.getDisplayValue()).algorithm("").build();
		actual = EqualsHashCodeAndToStringEvaluator.evaluateEqualsHashcodeAndToString(keyInfo);
		expected = true;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link KeyInfo} with {@link BeanTester}
	 */
	@Test
	@DisplayName("Test KeyInfo with BeanTester")
	public void testWithBeanTester()
	{
		BeanVerifier.forClass(KeyInfo.class).editSettings()
			.registerFactory(KeyInfo.class,
				() -> KeyInfo.builder().encoded(privateKey.getEncoded())
					.keyType(KeyType.PRIVATE_KEY.getDisplayValue())
					.algorithm(privateKey.getAlgorithm()).build())
			.edited().verify();
	}

	/**
	 * Test method for handling invalid data
	 */
	@Test
	@DisplayName("Test KeyInfo with invalid data")
	public void testInvalidData()
	{
		// Test for null keyType
		assertThrows(NullPointerException.class,
			() -> KeyInfo.builder().encoded(new byte[] { }).algorithm("algorithm").build());

		// Test for null encoded
		assertThrows(NullPointerException.class,
			() -> KeyInfo.builder().keyType("keyType").algorithm("algorithm").build());

		// Test for null algorithm
		assertThrows(NullPointerException.class,
			() -> KeyInfo.builder().encoded(new byte[] { }).keyType("keyType").build());
	}
}
