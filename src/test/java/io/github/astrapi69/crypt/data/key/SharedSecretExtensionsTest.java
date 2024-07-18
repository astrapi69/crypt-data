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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.model.KeyInfo;
import io.github.astrapi69.crypt.data.model.SharedSecretInfo;
import io.github.astrapi69.crypt.data.model.SharedSecretModel;

/**
 * The unit test class for {@link SharedSecretExtensions}.
 */
class SharedSecretExtensionsTest
{


	/**
	 * Test method for {@link SharedSecretExtensions#toModel(SharedSecretInfo)}.
	 *
	 * @throws Exception
	 *             if an error occurs during key generation or conversion
	 */
	@Test
	void testToModel() throws Exception
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(256);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		KeyInfo privateKeyInfo = new KeyInfo(KeyType.PRIVATE_KEY.getDisplayValue(),
			privateKey.getEncoded(), privateKey.getAlgorithm());
		KeyInfo publicKeyInfo = new KeyInfo(KeyType.PUBLIC_KEY.getDisplayValue(),
			publicKey.getEncoded(), publicKey.getAlgorithm());

		SharedSecretInfo info = SharedSecretInfo.builder().privateKeyInfo(privateKeyInfo)
			.publicKeyInfo(publicKeyInfo).keyAgreementAlgorithm("ECDH").secretKeyAlgorithm("AES")
			.provider("SunJCE").cipherAlgorithm("AES/CBC/PKCS5Padding").iv(new byte[16]).build();

		SharedSecretModel model = SharedSecretExtensions.toModel(info);

		assertNotNull(model);
		assertEquals(privateKey, model.getPrivateKey());
		assertEquals(publicKey, model.getPublicKey());
		assertEquals("ECDH", model.getKeyAgreementAlgorithm());
		assertEquals("AES", model.getSecretKeyAlgorithm());
		assertEquals("SunJCE", model.getProvider());
		assertEquals("AES/CBC/PKCS5Padding", model.getCipherAlgorithm());
		assertArrayEquals(new byte[16], model.getIv());
	}

	/**
	 * Test method for {@link SharedSecretExtensions#toInfo(SharedSecretModel)}.
	 *
	 * @throws Exception
	 *             if an error occurs during key generation or conversion
	 */
	@Test
	void testToInfo() throws Exception
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(256);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		SharedSecretModel model = SharedSecretModel.builder().privateKey(privateKey)
			.publicKey(publicKey).keyAgreementAlgorithm("ECDH").secretKeyAlgorithm("AES")
			.provider("SunJCE").cipherAlgorithm("AES/CBC/PKCS5Padding").iv(new byte[16]).build();

		SharedSecretInfo info = SharedSecretExtensions.toInfo(model);

		assertNotNull(info);
		assertEquals("ECDH", info.getKeyAgreementAlgorithm());
		assertEquals("AES", info.getSecretKeyAlgorithm());
		assertEquals("SunJCE", info.getProvider());
		assertEquals("AES/CBC/PKCS5Padding", info.getCipherAlgorithm());
		assertArrayEquals(new byte[16], info.getIv());
	}

}