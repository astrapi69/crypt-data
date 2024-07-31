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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.model.KeyInfo;
import io.github.astrapi69.crypt.data.model.SharedSecretInfo;
import io.github.astrapi69.crypt.data.model.SharedSecretModel;

/**
 * The unit test class for the class {@link KeyAgreementFactory}.
 */
class KeyAgreementFactoryTest
{

	private static KeyPair aliceKeyPair;
	private static KeyPair bobKeyPair;
	private static PublicKey bobPublicKey;


	private static PrivateKey privateKey;
	private static PublicKey publicKey;

	@BeforeAll
	static void setup() throws Exception
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(256);

		aliceKeyPair = keyPairGenerator.generateKeyPair();
		bobKeyPair = keyPairGenerator.generateKeyPair();

		byte[] bobPk = bobKeyPair.getPublic().getEncoded();
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		X509EncodedKeySpec bobPkSpec = new X509EncodedKeySpec(bobPk);
		bobPublicKey = keyFactory.generatePublic(bobPkSpec);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		privateKey = keyPair.getPrivate();
		publicKey = keyPair.getPublic();
	}


	@ParameterizedTest
	@CsvFileSource(resources = "/test-data.csv", numLinesToSkip = 1)
	@DisplayName("Test newSharedSecret with SharedSecretModel")
	void testNewSharedSecretFromModel(String privateKeyAlgorithm, String publicKeyAlgorithm,
		String keyAgreementAlgorithm, String secretKeyAlgorithm, String provider) throws Exception
	{
		SharedSecretModel sharedSecretModel = SharedSecretModel.builder().privateKey(privateKey)
			.publicKey(publicKey).keyAgreementAlgorithm(keyAgreementAlgorithm)
			.secretKeyAlgorithm(secretKeyAlgorithm)
			.provider("null".equals(provider) ? null : provider)
			.cipherAlgorithm("AES/CBC/PKCS5Padding").iv(new byte[16]).build();

		SecretKey secretKey = KeyAgreementFactory.newSharedSecret(sharedSecretModel);

		assertNotNull(secretKey);
		assertEquals(keyAgreementAlgorithm, secretKey.getAlgorithm());
	}

	@ParameterizedTest
	@CsvFileSource(resources = "/test-data.csv", numLinesToSkip = 1)
	@DisplayName("Test newSharedSecret with SharedSecretInfo")
	void testNewSharedSecretFromInfo(String privateKeyAlgorithm, String publicKeyAlgorithm,
		String keyAgreementAlgorithm, String secretKeyAlgorithm, String provider) throws Exception
	{
		KeyInfo privateKeyInfo = new KeyInfo(KeyType.PRIVATE_KEY.getDisplayValue(),
			privateKey.getEncoded(), privateKeyAlgorithm);
		KeyInfo publicKeyInfo = new KeyInfo(KeyType.PUBLIC_KEY.getDisplayValue(),
			publicKey.getEncoded(), publicKeyAlgorithm);

		SharedSecretInfo sharedSecretInfo = SharedSecretInfo.builder()
			.privateKeyInfo(privateKeyInfo).publicKeyInfo(publicKeyInfo)
			.keyAgreementAlgorithm(keyAgreementAlgorithm).secretKeyAlgorithm(secretKeyAlgorithm)
			.provider("null".equals(provider) ? null : provider)
			.cipherAlgorithm("AES/CBC/PKCS5Padding").iv(new byte[16]).build();

		SecretKey secretKey = KeyAgreementFactory.newSharedSecret(sharedSecretInfo);

		assertNotNull(secretKey);
		assertEquals(keyAgreementAlgorithm, secretKey.getAlgorithm());
	}

	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newKeyAgreement(PrivateKey, PublicKey, String, String, boolean)}.
	 */
	@Test
	void newKeyAgreement() throws Exception
	{
		// Create key agreement
		KeyAgreement aliceKeyAgreement = KeyAgreementFactory
			.newKeyAgreement(aliceKeyPair.getPrivate(), bobPublicKey, "ECDH", null, true);

		assertNotNull(aliceKeyAgreement);
	}

	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newSharedSecret(PrivateKey, PublicKey, String, String, boolean)}.
	 */
	@Test
	void newSharedSecret() throws Exception
	{
		KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH");
		aliceKeyAgreement.init(aliceKeyPair.getPrivate());
		aliceKeyAgreement.doPhase(bobPublicKey, true);

		byte[] expected = aliceKeyAgreement.generateSecret();

		byte[] actual = KeyAgreementFactory.newSharedSecret(aliceKeyPair.getPrivate(), bobPublicKey,
			"ECDH", null, true);
		assertNotNull(actual);
		assertArrayEquals(expected, actual);
	}

	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newSharedSecret(PrivateKey, PublicKey, String, String, boolean)}.
	 */
	@Test
	void newSharedSecretWithSecretKeyAlgorithm() throws Exception
	{
		SecretKey secretKey = KeyAgreementFactory.newSharedSecret(aliceKeyPair.getPrivate(),
			bobPublicKey, "ECDH", "AES", null, true);

		assertNotNull(secretKey);
	}

	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newSharedSecret(PrivateKey, PublicKey, String, String)}.
	 */
	@Test
	void newSharedSecretWithProvider() throws Exception
	{
		SecretKey secretKey = KeyAgreementFactory.newSharedSecret(aliceKeyPair.getPrivate(),
			bobPublicKey, "ECDH", "AES", null);

		assertNotNull(secretKey);
	}

	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newSharedSecret(PrivateKey, PublicKey, String, String, boolean)}
	 * with invalid key.
	 */
	@Test
	void newSharedSecretInvalidKey() throws Exception
	{
		assertThrows(InvalidKeyException.class, () -> {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair invalidKeyPair = keyPairGenerator.generateKeyPair();

			KeyAgreementFactory.newSharedSecret(invalidKeyPair.getPrivate(), bobPublicKey, "ECDH",
				"AES", null, true);
		});
	}

	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newKeyAgreement(PrivateKey, PublicKey, String, String, boolean)}
	 * with no such algorithm.
	 */
	@Test
	void newKeyAgreementNoSuchAlgorithm() throws Exception
	{
		assertThrows(NoSuchAlgorithmException.class, () -> {
			KeyAgreementFactory.newKeyAgreement(aliceKeyPair.getPrivate(), bobPublicKey, "INVALID",
				null, true);
		});
	}

	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newSharedSecret(PrivateKey, PublicKey, String, String, boolean)}
	 * with no such provider.
	 */
	@Test
	void newSharedSecretNoSuchProvider() throws Exception
	{
		assertThrows(NoSuchProviderException.class, () -> {
			KeyAgreementFactory.newSharedSecret(aliceKeyPair.getPrivate(), bobPublicKey, "ECDH",
				"AES", "INVALID", true);
		});
	}

	/**
	 * Test method for {@link KeyAgreementFactory} with {@link BeanTester}.
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyAgreementFactory.class);
	}


	/**
	 * Test method for
	 * {@link KeyAgreementFactory#newSharedSecret(PrivateKey, PublicKey, String, String)}
	 */
	@Test
	@DisplayName("Test newSharedSecret with provider")
	void testNewSharedSecretWithProvider() throws Exception
	{
		byte[] sharedSecret = KeyAgreementFactory.newSharedSecret(aliceKeyPair.getPrivate(),
			bobPublicKey, "ECDH", null);

		assertNotNull(sharedSecret);

		KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
		keyAgreement.init(aliceKeyPair.getPrivate());
		keyAgreement.doPhase(bobPublicKey, true);
		byte[] expectedSecret = keyAgreement.generateSecret();

		assertArrayEquals(expectedSecret, sharedSecret);
	}

}
