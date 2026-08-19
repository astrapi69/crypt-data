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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * The unit test class for the class {@link HkdfExtensions}
 */
public class HkdfExtensionsTest
{

	/**
	 * Test method for {@link HkdfExtensions#deriveKey(byte[], byte[], byte[], int)}
	 */
	@Test
	public void testDeriveKeySameInputProducesSameOutput()
	{
		byte[] ikm = "input key material".getBytes();
		byte[] salt = "salt".getBytes();
		byte[] info = "context info".getBytes();

		byte[] first = HkdfExtensions.deriveKey(ikm, salt, info, 32);
		byte[] second = HkdfExtensions.deriveKey(ikm, salt, info, 32);

		assertArrayEquals(first, second);
	}

	/**
	 * Test method for {@link HkdfExtensions#deriveKey(byte[], byte[], byte[], int)}
	 */
	@Test
	public void testDeriveKeyReturnsRequestedLength()
	{
		byte[] ikm = "input key material".getBytes();
		byte[] salt = "salt".getBytes();
		byte[] info = "context info".getBytes();

		byte[] key16 = HkdfExtensions.deriveKey(ikm, salt, info, 16);
		byte[] key32 = HkdfExtensions.deriveKey(ikm, salt, info, 32);

		assertNotNull(key16);
		assertNotNull(key32);
		assertEquals(16, key16.length);
		assertEquals(32, key32.length);
	}

	/**
	 * Test method for {@link HkdfExtensions#deriveKey(byte[], byte[], byte[], int)}
	 */
	@Test
	public void testDeriveKeyDifferentSaltProducesDifferentOutput()
	{
		byte[] ikm = "input key material".getBytes();
		byte[] info = "context info".getBytes();

		byte[] first = HkdfExtensions.deriveKey(ikm, "salt-one".getBytes(), info, 32);
		byte[] second = HkdfExtensions.deriveKey(ikm, "salt-two".getBytes(), info, 32);

		assertFalse(Arrays.equals(first, second));
	}

	/**
	 * Test method for {@link HkdfExtensions#deriveKey(byte[], byte[], byte[], int)}
	 */
	@Test
	public void testDeriveKeyDifferentInfoProducesDifferentOutput()
	{
		byte[] ikm = "input key material".getBytes();
		byte[] salt = "salt".getBytes();

		byte[] first = HkdfExtensions.deriveKey(ikm, salt, "info-one".getBytes(), 32);
		byte[] second = HkdfExtensions.deriveKey(ikm, salt, "info-two".getBytes(), 32);

		assertFalse(Arrays.equals(first, second));
	}

	/**
	 * Test method for {@link HkdfExtensions#deriveKey(byte[], byte[], byte[], int)}
	 */
	@Test
	public void testDeriveKeyNullInputKeyMaterialThrows()
	{
		assertThrows(NullPointerException.class,
			() -> HkdfExtensions.deriveKey(null, "salt".getBytes(), "info".getBytes(), 32));
	}

}
