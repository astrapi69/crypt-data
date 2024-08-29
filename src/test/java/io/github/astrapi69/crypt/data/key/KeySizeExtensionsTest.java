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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.data.algorithm.AlgorithmExtensions;

/**
 * The unit test class for the class {@link KeySizeExtensions}
 */
class KeySizeExtensionsTest
{

	/**
	 * Test method for {@link KeySizeExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeySizeExtensions.class);
	}

	/**
	 * Test method for {@link KeySizeExtensions#getSupportedKeySizesForKeyGenerator(String)}
	 *
	 * @throws NoSuchMethodException
	 *             if the specified method cannot be found
	 * @throws InvocationTargetException
	 *             if the underlying method throws an exception
	 * @throws IllegalAccessException
	 *             if the method is inaccessible
	 */
	@Test
	@Disabled("only for print algorithms and key sizes")
	public void testGetSupportedKeySizesForKeyGeneratorForKeyPairGenerator()
		throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
	{
		Set<String> keyPairGeneratorAlgorithms = AlgorithmExtensions
			.getAlgorithms("KeyPairGenerator");
		assertNotNull(keyPairGeneratorAlgorithms);
		Map<String, Set<Integer>> supportedKeySizesForKeyPairGenerator = AlgorithmExtensions
			.getSupportedAlgorithmsAndKeySizes("KeyPairGenerator", KeyPairGenerator.class,
				KeyPairGenerator::initialize, 1, 32768, 1);
		assertEquals(keyPairGeneratorAlgorithms.size(),
			supportedKeySizesForKeyPairGenerator.size());
		supportedKeySizesForKeyPairGenerator.forEach((algorithm, keySizes) -> {
			keySizes.forEach(keySize -> {
				System.out.println(algorithm + "," + keySize);
			});
		});
	}

	/**
	 * Test method for {@link KeySizeExtensions#getSupportedKeySizesForKeyGenerator(String)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             if the specified algorithm is not available
	 */
	@Test
	public void testGetSupportedKeySizesForKeyGeneratorForKeyGenerator()
		throws NoSuchAlgorithmException
	{
		Set<String> keyGeneratorAlgorithms = AlgorithmExtensions.getAlgorithms("KeyGenerator");
		assertNotNull(keyGeneratorAlgorithms);
		for (String keyGeneratorAlgorithm : keyGeneratorAlgorithms)
		{
			Set<Integer> supportedKeySizes = KeySizeExtensions
				.getSupportedKeySizesForKeyGenerator(keyGeneratorAlgorithm);
			assertNotNull(supportedKeySizes);
		}
		Set<Integer> aesKeySizes = KeySizeExtensions.getSupportedKeySizesForKeyGenerator("AES");
		assertNotNull(aesKeySizes, "The result should not be null");
		assertTrue(aesKeySizes.contains(128), "AES should support 128-bit keys");
		assertTrue(aesKeySizes.contains(192), "AES should support 192-bit keys");
		assertTrue(aesKeySizes.contains(256), "AES should support 256-bit keys");

		Set<Integer> desKeySizes = KeySizeExtensions.getSupportedKeySizesForKeyGenerator("DES");
		assertNotNull(desKeySizes, "The result should not be null");
		assertTrue(desKeySizes.contains(56), "DES should support 56-bit keys");
	}

	/**
	 * Test method for {@link KeySizeExtensions#getSupportedKeySizesForKeyPairGenerator(String)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             if the specified algorithm is not available
	 * @throws NoSuchMethodException
	 *             if the specified method cannot be found
	 * @throws InvocationTargetException
	 *             if the underlying method throws an exception
	 * @throws IllegalAccessException
	 *             if the method is inaccessible
	 */
	@Test
	public void testGetSupportedKeySizesForKeyPairGenerator() throws NoSuchAlgorithmException,
		NoSuchMethodException, InvocationTargetException, IllegalAccessException
	{
		Set<String> keyGeneratorAlgorithms = AlgorithmExtensions.getAlgorithms("KeyPairGenerator");
		assertNotNull(keyGeneratorAlgorithms);
		for (String keyGeneratorAlgorithm : keyGeneratorAlgorithms)
		{
			Set<Integer> keySizes = KeySizeExtensions
				.getSupportedKeySizesForKeyPairGenerator(keyGeneratorAlgorithm);
			assertNotNull(keySizes);
		}
		Set<Integer> rsaKeySizes = KeySizeExtensions.getSupportedKeySizesForKeyPairGenerator("RSA");
		assertNotNull(rsaKeySizes, "The result should not be null");
		assertTrue(rsaKeySizes.contains(1024), "RSA should support 1024-bit keys");
		assertTrue(rsaKeySizes.contains(2048), "RSA should support 2048-bit keys");
		assertTrue(rsaKeySizes.contains(4096), "RSA should support 4096-bit keys");

		Set<Integer> dsaKeySizes = KeySizeExtensions.getSupportedKeySizesForKeyPairGenerator("DSA");
		assertNotNull(dsaKeySizes, "The result should not be null");
		assertTrue(dsaKeySizes.contains(1024), "DSA should support 1024-bit keys");
		assertTrue(dsaKeySizes.contains(2048), "DSA should support 2048-bit keys");
		assertTrue(dsaKeySizes.contains(3072), "DSA should support 3072-bit keys");

	}

	/**
	 * Test method for {@link KeySizeExtensions#getSupportedKeySizesForKeyGenerator(String)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             if the specified algorithm is not available
	 */
	@Test
	public void testGetSupportedKeySizesForKeyGenerator() throws NoSuchAlgorithmException
	{
		Set<String> keyGeneratorAlgorithms = AlgorithmExtensions.getAlgorithms("KeyGenerator");
		assertNotNull(keyGeneratorAlgorithms);
		for (String keyGeneratorAlgorithm : keyGeneratorAlgorithms)
		{
			Set<Integer> supportedKeySizes = KeySizeExtensions
				.getSupportedKeySizesForKeyGenerator(keyGeneratorAlgorithm);
			assertNotNull(supportedKeySizes);
		}
		Set<Integer> aesKeySizes = KeySizeExtensions.getSupportedKeySizesForKeyGenerator("AES");
		assertNotNull(aesKeySizes, "The result should not be null");
		assertTrue(aesKeySizes.contains(128), "AES should support 128-bit keys");
		assertTrue(aesKeySizes.contains(192), "AES should support 192-bit keys");
		assertTrue(aesKeySizes.contains(256), "AES should support 256-bit keys");

		Set<Integer> desKeySizes = KeySizeExtensions.getSupportedKeySizesForKeyGenerator("DES");
		assertNotNull(desKeySizes, "The result should not be null");
		assertTrue(desKeySizes.contains(56), "DES should support 56-bit keys");
	}

	/**
	 * Test method for
	 * {@link KeySizeExtensions#getSupportedKeySizesForAlgorithmParameterGenerator(String)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             if the specified algorithm is not available
	 * @throws NoSuchMethodException
	 *             if the specified method cannot be found
	 * @throws InvocationTargetException
	 *             if the underlying method throws an exception
	 * @throws IllegalAccessException
	 *             if the method is inaccessible
	 */
	@Test
	public void testGetSupportedKeySizesForAlgorithmParameterGenerator()
		throws NoSuchAlgorithmException, NoSuchMethodException, InvocationTargetException,
		IllegalAccessException
	{
		Set<String> keyGeneratorAlgorithms = AlgorithmExtensions
			.getAlgorithms("AlgorithmParameterGenerator");
		assertNotNull(keyGeneratorAlgorithms);
		for (String keyGeneratorAlgorithm : keyGeneratorAlgorithms)
		{
			Set<Integer> supportedKeySizes = KeySizeExtensions
				.getSupportedKeySizesForAlgorithmParameterGenerator(keyGeneratorAlgorithm);
			assertNotNull(supportedKeySizes);
		}
	}

	/**
	 * Edge case test method for
	 * {@link KeySizeExtensions#getSupportedKeySizesForKeyPairGenerator(String)} with boundary
	 * values
	 *
	 * @throws NoSuchAlgorithmException
	 *             if the specified algorithm is not available
	 * @throws NoSuchMethodException
	 *             if the specified method cannot be found
	 * @throws InvocationTargetException
	 *             if the underlying method throws an exception
	 * @throws IllegalAccessException
	 *             if the method is inaccessible
	 */
	@Test
	public void testKeyPairGeneratorEdgeCases() throws NoSuchAlgorithmException,
		NoSuchMethodException, InvocationTargetException, IllegalAccessException
	{
		Set<Integer> rsaKeySizes = KeySizeExtensions.getSupportedKeySizesForKeyPairGenerator("RSA");
		assertNotNull(rsaKeySizes, "The result should not be null");
		assertFalse(rsaKeySizes.contains(511), "RSA should not support 511-bit keys");
		assertTrue(rsaKeySizes.contains(512), "RSA should support 512-bit keys");
		assertTrue(rsaKeySizes.contains(8192), "RSA should support 8192-bit keys");
		assertFalse(rsaKeySizes.contains(8193), "RSA should not support 8193-bit keys");
	}

	/**
	 * Edge case test method for
	 * {@link KeySizeExtensions#getSupportedKeySizesForKeyGenerator(String)} with boundary values
	 *
	 * @throws NoSuchAlgorithmException
	 *             if the specified algorithm is not available
	 */
	@Test
	public void testKeyGeneratorEdgeCases() throws NoSuchAlgorithmException
	{
		Set<Integer> aesKeySizes = KeySizeExtensions.getSupportedKeySizesForKeyGenerator("AES");
		assertNotNull(aesKeySizes, "The result should not be null");
		assertTrue(aesKeySizes.contains(128), "AES should support 128-bit keys");
		assertTrue(aesKeySizes.contains(192), "AES should support 192-bit keys");
		assertTrue(aesKeySizes.contains(256), "AES should support 256-bit keys");
	}

	/**
	 * Edge case test method for
	 * {@link KeySizeExtensions#getSupportedKeySizesForAlgorithmParameterGenerator(String)} with
	 * boundary values
	 *
	 * @throws NoSuchAlgorithmException
	 *             if the specified algorithm is not available
	 * @throws NoSuchMethodException
	 *             if the specified method cannot be found
	 * @throws InvocationTargetException
	 *             if the underlying method throws an exception
	 * @throws IllegalAccessException
	 *             if the method is inaccessible
	 */
	@Test
	public void testAlgorithmParameterGeneratorEdgeCases() throws NoSuchAlgorithmException,
		NoSuchMethodException, InvocationTargetException, IllegalAccessException
	{
		Set<Integer> dsaKeySizes = KeySizeExtensions
			.getSupportedKeySizesForAlgorithmParameterGenerator("DSA");
		assertNotNull(dsaKeySizes, "The result should not be null");
		assertFalse(dsaKeySizes.contains(0), "DSA should not support 0-bit keys");
		assertTrue(dsaKeySizes.contains(512), "DSA should support 512-bit keys");
		assertTrue(dsaKeySizes.contains(3072), "DSA should support 3072-bit keys");
		assertFalse(dsaKeySizes.contains(3073), "DSA should not support 3073-bit keys");
	}
}
