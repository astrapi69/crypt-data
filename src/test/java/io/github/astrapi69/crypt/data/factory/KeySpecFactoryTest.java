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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidKeyException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm;

/**
 * The unit test class for the class {@link KeySpecFactory}
 */
public class KeySpecFactoryTest
{

	/**
	 * Test method for {@link KeySpecFactory#newPBEKeySpec(String)}
	 */
	@Test
	public void testNewPBEKeySpecString() throws Exception
	{
		KeySpec actual;

		actual = KeySpecFactory.newPBEKeySpec(CompoundAlgorithm.PASSWORD);
		assertNotNull(actual);

		actual = KeySpecFactory.newPBEKeySpec(null);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link KeySpecFactory#newPBEKeySpec(String, byte[], int)}
	 */
	@Test
	public void testNewPBEKeySpecStringByteArrayInt() throws Exception
	{
		KeySpec actual;

		actual = KeySpecFactory.newPBEKeySpec(CompoundAlgorithm.PASSWORD, CompoundAlgorithm.SALT,
			CompoundAlgorithm.ITERATIONCOUNT);
		assertNotNull(actual);

		actual = KeySpecFactory.newPBEKeySpec(null, CompoundAlgorithm.SALT,
			CompoundAlgorithm.ITERATIONCOUNT);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link KeySpecFactory#newSecretKeySpec(byte[], String)}
	 */
	@Test
	public void testNewSecretKeySpecByteArrayString() throws Exception
	{
		String algorithm;
		String key;
		SecretKeySpec secretKeySpec;

		algorithm = AesAlgorithm.AES.getAlgorithm();
		key = "1234567890123456";
		secretKeySpec = KeySpecFactory.newSecretKeySpec(key.getBytes(), algorithm);
		assertNotNull(secretKeySpec);
	}

	/**
	 * Test method for {@link KeySpecFactory#newSecretKeySpec(byte[], int, int, String)}
	 */
	@Test
	public void testNewSecretKeySpecByteArrayIntIntString() throws Exception
	{
		String algorithm;
		String key;
		SecretKeySpec secretKeySpec;

		algorithm = AesAlgorithm.AES.getAlgorithm();
		key = "1234567890123456";
		secretKeySpec = KeySpecFactory.newSecretKeySpec(key.getBytes(), 0, 16, algorithm);
		assertNotNull(secretKeySpec);
	}

	/**
	 * Test method for {@link KeySpecFactory#newDESKeySpec(byte[])}
	 */
	@Test
	public void testNewDESKeySpec() throws Exception
	{
		byte[] key = "12345678".getBytes();
		DESKeySpec desKeySpec = KeySpecFactory.newDESKeySpec(key);
		assertNotNull(desKeySpec);

		assertThrows(InvalidKeyException.class, () -> {
			KeySpecFactory.newDESKeySpec("short".getBytes());
		});
	}

	/**
	 * Test method for {@link KeySpecFactory#newDESedeKeySpec(byte[])}
	 */
	@Test
	public void testNewDESedeKeySpec() throws Exception
	{
		byte[] key = "123456789012345678901234".getBytes();
		DESedeKeySpec desedeKeySpec = KeySpecFactory.newDESedeKeySpec(key);
		assertNotNull(desedeKeySpec);

		assertThrows(InvalidKeyException.class, () -> {
			KeySpecFactory.newDESedeKeySpec("short".getBytes());
		});
	}

	/**
	 * Test method for {@link KeySpecFactory#newSecretKeySpec(String, int)}
	 */
	@Test
	public void testNewSecretKeySpecStringInt() throws Exception
	{
		String algorithm;
		SecretKeySpec secretKeySpec;

		algorithm = AesAlgorithm.AES.getAlgorithm();
		secretKeySpec = KeySpecFactory.newSecretKeySpec(algorithm, 128);
		assertNotNull(secretKeySpec);
	}

	/**
	 * Test method for {@link KeySpecFactory} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeySpecFactory.class);
	}

	/**
	 * Test method for {@link KeySpecFactory#newSecretKey(byte[], String)}
	 */
	@Test
	public void testNewSecretKey()
	{
		String algorithm;
		byte[] decryptedKey;
		SecretKey secretKey;

		algorithm = AesAlgorithm.AES.getAlgorithm();
		decryptedKey = "1234567890123456".getBytes();
		secretKey = KeySpecFactory.newSecretKey(decryptedKey, algorithm);
		assertNotNull(secretKey);

		// Test with null key
		assertThrows(NullPointerException.class, () -> {
			KeySpecFactory.newSecretKey(null, algorithm);
		});

		// Test with empty key
		assertThrows(IllegalArgumentException.class, () -> {
			KeySpecFactory.newSecretKey(new byte[0], algorithm);
		});

		// Test with null algorithm
		assertThrows(IllegalArgumentException.class, () -> {
			KeySpecFactory.newSecretKey(decryptedKey, null);
		});

	}
}
