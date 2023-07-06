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

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.hex.HexExtensions;

/**
 * The unit test class for the class {@link KeyExtensions}
 */
class KeyExtensionsTest
{

	/**
	 * Test method for format key
	 */
	@Test
	public void testFormatKey() throws NoSuchAlgorithmException
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
}