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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidKeyException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

/**
 * The unit test class for the class {@link KeyWrapFactory}
 */
public class KeyWrapFactoryTest
{

	private SecretKey newAesKey(final int bits) throws Exception
	{
		final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(bits);
		return keyGenerator.generateKey();
	}

	/**
	 * Test method for {@link KeyWrapFactory#wrap(SecretKey, Key)} and
	 * {@link KeyWrapFactory#unwrap(SecretKey, byte[], String, int)}
	 */
	@Test
	public void testWrapAndUnwrapRoundtrip() throws Exception
	{
		final SecretKey keyEncryptionKey = newAesKey(256);
		final SecretKey dataKey = newAesKey(256);

		final byte[] wrapped = KeyWrapFactory.wrap(keyEncryptionKey, dataKey);

		final Key unwrapped = KeyWrapFactory.unwrap(keyEncryptionKey, wrapped, "AES",
			Cipher.SECRET_KEY);

		assertArrayEquals(dataKey.getEncoded(), unwrapped.getEncoded());
		assertEquals(dataKey.getAlgorithm(), unwrapped.getAlgorithm());
	}

	/**
	 * Test method for {@link KeyWrapFactory#wrap(SecretKey, Key)} with a smaller data key than the
	 * key-encryption key
	 */
	@Test
	public void testWrapSmallerDataKey() throws Exception
	{
		final SecretKey keyEncryptionKey = newAesKey(256);
		final SecretKey dataKey = newAesKey(128);

		final byte[] wrapped = KeyWrapFactory.wrap(keyEncryptionKey, dataKey);
		final Key unwrapped = KeyWrapFactory.unwrap(keyEncryptionKey, wrapped, "AES",
			Cipher.SECRET_KEY);

		assertArrayEquals(dataKey.getEncoded(), unwrapped.getEncoded());
	}

	/**
	 * Test method for {@link KeyWrapFactory#unwrap(SecretKey, byte[], String, int)} with tampered
	 * wrapped bytes
	 */
	@Test
	public void testUnwrapFailsForTamperedWrappedBytes() throws Exception
	{
		final SecretKey keyEncryptionKey = newAesKey(256);
		final SecretKey dataKey = newAesKey(256);

		final byte[] wrapped = KeyWrapFactory.wrap(keyEncryptionKey, dataKey);
		wrapped[0] ^= 0xFF;

		assertThrows(InvalidKeyException.class,
			() -> KeyWrapFactory.unwrap(keyEncryptionKey, wrapped, "AES", Cipher.SECRET_KEY));
	}

	/**
	 * Test method for {@link KeyWrapFactory#unwrap(SecretKey, byte[], String, int)} with the wrong
	 * key-encryption key
	 */
	@Test
	public void testUnwrapFailsForWrongKeyEncryptionKey() throws Exception
	{
		final SecretKey keyEncryptionKey = newAesKey(256);
		final SecretKey wrongKeyEncryptionKey = newAesKey(256);
		final SecretKey dataKey = newAesKey(256);

		final byte[] wrapped = KeyWrapFactory.wrap(keyEncryptionKey, dataKey);

		assertThrows(InvalidKeyException.class,
			() -> KeyWrapFactory.unwrap(wrongKeyEncryptionKey, wrapped, "AES", Cipher.SECRET_KEY));
	}

}
