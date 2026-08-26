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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.key.PemType;
import io.github.astrapi69.crypt.data.key.reader.PemObjectReader;

/**
 * Unit tests for {@link PrivateKeyExtensions#fromPKCS1ToPemFormat(byte[])}, which the private key
 * writer no longer calls: it takes bytes rather than a key, so it cannot tell which algorithm they
 * belong to and always writes the RSA header.
 */
class FromPkcs1ToPemFormatTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static PrivateKey newRsaPrivateKey() throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA",
			BouncyCastleProvider.PROVIDER_NAME);
		generator.initialize(2048);
		return generator.generateKeyPair().getPrivate();
	}

	@Test
	void wrapsTheGivenBytesUnderTheRsaHeaderUnchanged() throws Exception
	{
		byte[] pkcs1 = PrivateKeyExtensions.toPKCS1Format(newRsaPrivateKey());

		String pem = PrivateKeyExtensions.fromPKCS1ToPemFormat(pkcs1);

		assertTrue(pem.startsWith("-----BEGIN " + PemType.RSA_PRIVATE_KEY.getName() + "-----"),
			pem);
		PemObject pemObject = PemObjectReader.getPemObject(pem);
		assertEquals(PemType.RSA_PRIVATE_KEY.getName(), pemObject.getType());
		assertArrayEquals(pkcs1, pemObject.getContent(),
			"the bytes must be wrapped, not transformed");
	}

	/**
	 * The limitation this pins, so it is not mistaken for a defect: with only bytes to go on there
	 * is nothing to tell an EC key from an RSA one, so the RSA header is written either way. That
	 * is why the writer uses {@link PrivateKeyExtensions#toPemFormat(PrivateKey)} instead.
	 */
	@Test
	void writesTheRsaHeaderEvenForBytesThatAreNotRsa() throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC",
			BouncyCastleProvider.PROVIDER_NAME);
		PrivateKey ecPrivateKey = generator.generateKeyPair().getPrivate();
		byte[] ecPkcs1 = PrivateKeyExtensions.toPKCS1Format(ecPrivateKey);

		String pem = PrivateKeyExtensions.fromPKCS1ToPemFormat(ecPkcs1);

		assertTrue(pem.startsWith("-----BEGIN " + PemType.RSA_PRIVATE_KEY.getName() + "-----"),
			"it cannot know better from bytes alone, but " + PemType.EC_PRIVATE_KEY.getName()
				+ " is what an EC key needs: " + pem);
		assertTrue(
			PrivateKeyExtensions.toPemFormat(ecPrivateKey)
				.startsWith("-----BEGIN " + PemType.EC_PRIVATE_KEY.getName() + "-----"),
			"toPemFormat has the key and gets the header right");
	}
}
