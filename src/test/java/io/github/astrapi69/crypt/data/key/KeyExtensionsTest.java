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

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.data.hex.HexExtensions;

/**
 * The unit test class for the class {@link KeyExtensions}
 */
@DisplayName("Unit tests for KeyExtensions")
class KeyExtensionsTest
{

	/**
	 * Helper method to format a {@link Key} into a readable {@link String}.
	 *
	 * @param key
	 *            the {@link Key} to format
	 * @return the formatted {@link String} representation of the {@link Key}
	 */
	private static String formatKey(Key key)
	{
		StringBuffer sb = new StringBuffer();
		String algo = key.getAlgorithm();
		String fmt = key.getFormat();
		byte[] encoded = key.getEncoded();
		sb.append(
			"Key[algorithm=" + algo + ", format=" + fmt + ", bytes=" + encoded.length + "]\n");
		if (fmt.equalsIgnoreCase("RAW"))
		{
			sb.append("Key Material (in hex):: ");
			sb.append(HexExtensions.encodeHex(key.getEncoded()));
		}
		return sb.toString();
	}

	/**
	 * Test method for formatting various keys.
	 */
	@Test
	@DisplayName("Test formatting of various keys")
	void testFormatKey() throws NoSuchAlgorithmException
	{
		KeyGenerator kg = KeyGenerator.getInstance("DES");
		kg.init(56); // 56 is the keysize. Fixed for DES
		SecretKey key = kg.generateKey();
		String formatKey = formatKey(key);
		System.out.println(formatKey);

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		kpg.initialize(512); // 512 is the keysize.
		KeyPair kp = kpg.generateKeyPair();
		PublicKey pubk = kp.getPublic();
		PrivateKey prvk = kp.getPrivate();
		System.out.println("Generated Public Key:: " + formatKey(pubk));
		System.out.println("Generated Private Key:: " + formatKey(prvk));
	}

	/**
	 * Test method for base64 encoding and decoding.
	 */
	@Test
	@DisplayName("Test base64 encoding and decoding")
	void testBase64EncodingDecoding()
	{
		byte[] originalKey = { 1, 2, 3, 4, 5 };
		String base64Encoded = KeyExtensions.toBase64(originalKey);
		byte[] decodedKey = KeyExtensions.decodeBase64(base64Encoded);
		assertArrayEquals(originalKey, decodedKey);
	}

	/**
	 * Test method for base64 binary encoding and decoding.
	 */
	@Test
	@DisplayName("Test base64 binary encoding and decoding")
	void testBase64BinaryEncodingDecoding()
	{
		byte[] originalKey = { 1, 2, 3, 4, 5 };
		String base64BinaryEncoded = KeyExtensions.toBase64Binary(originalKey);
		byte[] decodedKey = KeyExtensions.decodeBase64(base64BinaryEncoded);
		assertArrayEquals(originalKey, decodedKey);
	}

	/**
	 * Test method for getting algorithm, format, and encoded key.
	 */
	@Test
	@DisplayName("Test getAlgorithm, getFormat, and getEncoded methods")
	void testKeyAttributes() throws NoSuchAlgorithmException
	{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		kpg.initialize(512); // 512 is the keysize.
		KeyPair kp = kpg.generateKeyPair();
		PublicKey pubk = kp.getPublic();
		PrivateKey prvk = kp.getPrivate();

		assertEquals("DSA", KeyExtensions.getAlgorithm(pubk));
		assertEquals("X.509", KeyExtensions.getFormat(pubk));
		assertArrayEquals(pubk.getEncoded(), KeyExtensions.getEncoded(pubk));

		assertEquals("DSA", KeyExtensions.getAlgorithm(prvk));
		assertEquals("PKCS#8", KeyExtensions.getFormat(prvk));
		assertArrayEquals(prvk.getEncoded(), KeyExtensions.getEncoded(prvk));
	}

	/**
	 * Test method for {@link KeyExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyExtensions.class);
	}
}
