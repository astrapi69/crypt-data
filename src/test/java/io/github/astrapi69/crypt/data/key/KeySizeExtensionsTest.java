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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import javax.crypto.KeyGenerator;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
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
	 * One key generator algorithm with sizes it must and must not support
	 *
	 * @param algorithm
	 *            the key generator algorithm
	 * @param supported
	 *            key sizes that must be reported
	 * @param probes
	 *            key sizes that are cross-checked against a fresh {@link KeyGenerator}: a probe
	 *            must be reported if and only if the generator accepts it. Whether a given provider
	 *            accepts e.g. AES-512 differs between SunJCE and BouncyCastle, so this is
	 *            deliberately not hardcoded
	 */
	record KeyGeneratorCase(String algorithm, Set<Integer> supported, Set<Integer> probes) {
	}

	static Stream<KeyGeneratorCase> keyGeneratorCases()
	{
		return Stream.of(new KeyGeneratorCase("AES", Set.of(128, 192, 256), Set.of(1, 127, 512)),
			new KeyGeneratorCase("DES", Set.of(56), Set.of(1, 55, 57, 128)),
			new KeyGeneratorCase("HmacSHA256", Set.of(256), Set.of(1, 8192)));
	}

	/**
	 * Test method for {@link KeySizeExtensions#getSupportedKeySizesForKeyGenerator(String)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws NoSuchAlgorithmException
	 *             if the specified algorithm is not available
	 */
	@ParameterizedTest
	@MethodSource("keyGeneratorCases")
	void testGetSupportedKeySizesForKeyGenerator(final KeyGeneratorCase testCase)
		throws NoSuchAlgorithmException
	{
		Set<Integer> keySizes = KeySizeExtensions
			.getSupportedKeySizesForKeyGenerator(testCase.algorithm());

		assertNotNull(keySizes);
		assertTrue(keySizes.containsAll(testCase.supported()), testCase.toString());
		// the scan covers exactly 1..8192; nothing outside that range can ever be reported
		assertFalse(keySizes.contains(0), "0 is outside the scanned range");
		assertFalse(keySizes.contains(8193), "8193 is outside the scanned range");
		for (Integer size : keySizes)
		{
			assertTrue(1 <= size && size <= 8192, "reported size out of range: " + size);
		}
		// cross-check: reported <=> accepted by the provider that actually serves the algorithm
		for (Integer probe : testCase.probes())
		{
			assertEquals(keyGeneratorAccepts(testCase.algorithm(), probe), keySizes.contains(probe),
				testCase.algorithm() + " size " + probe);
		}
	}

	private static boolean keyGeneratorAccepts(final String algorithm, final int keySize)
		throws NoSuchAlgorithmException
	{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		try
		{
			keyGenerator.init(keySize);
			keyGenerator.generateKey();
			return true;
		}
		catch (RuntimeException e)
		{
			return false;
		}
	}

	/**
	 * Test method for {@link KeySizeExtensions#getSupportedKeySizesForKeyGenerator(String)} with an
	 * algorithm no provider offers
	 */
	@Test
	void testGetSupportedKeySizesForKeyGeneratorUnknownAlgorithm()
	{
		assertThrows(NoSuchAlgorithmException.class,
			() -> KeySizeExtensions.getSupportedKeySizesForKeyGenerator("NoSuchKeyGenerator"));
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
