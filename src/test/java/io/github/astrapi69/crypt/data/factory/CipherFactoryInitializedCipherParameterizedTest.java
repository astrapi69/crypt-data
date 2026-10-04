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

import java.nio.charset.StandardCharsets;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized test for {@link CipherFactory#newCipher(int, SecretKey, String)} and
 * {@link CipherFactory#newCipher(int, SecretKey, AlgorithmParameterSpec, String)}: the returned
 * cipher must already be initialized in the requested mode, so it can be used directly
 */
class CipherFactoryInitializedCipherParameterizedTest
{

	private static final byte[] KEY_BYTES = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
	private static final byte[] IV_BYTES = "fedcba9876543210".getBytes(StandardCharsets.US_ASCII);
	private static final byte[] PLAIN_TEXT = "sixteen byte msg".getBytes(StandardCharsets.UTF_8);

	/**
	 * One cipher transformation with its key and optional parameter spec
	 *
	 * @param transformation
	 *            the cipher transformation
	 * @param key
	 *            the secret key
	 * @param paramSpec
	 *            the algorithm parameter spec or null for the overload without a spec
	 */
	record CipherCase(String transformation, SecretKey key, AlgorithmParameterSpec paramSpec) {
	}

	static Stream<CipherCase> cipherCases()
	{
		SecretKey aesKey = new SecretKeySpec(KEY_BYTES, "AES");
		return Stream.of(new CipherCase("AES/ECB/PKCS5Padding", aesKey, null),
			new CipherCase("AES", aesKey, null),
			new CipherCase("AES/CBC/PKCS5Padding", aesKey, new IvParameterSpec(IV_BYTES)),
			new CipherCase("AES/CTR/NoPadding", aesKey, new IvParameterSpec(IV_BYTES)));
	}

	private static Cipher newCipher(final int mode, final CipherCase testCase) throws Exception
	{
		if (testCase.paramSpec() == null)
		{
			return CipherFactory.newCipher(mode, testCase.key(), testCase.transformation());
		}
		return CipherFactory.newCipher(mode, testCase.key(), testCase.paramSpec(),
			testCase.transformation());
	}

	/**
	 * Test method for {@link CipherFactory#newCipher(int, SecretKey, String)} and
	 * {@link CipherFactory#newCipher(int, SecretKey, AlgorithmParameterSpec, String)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the cipher cannot be created or used
	 */
	@ParameterizedTest
	@MethodSource("cipherCases")
	void newCipherIsInitializedForTheRequestedMode(final CipherCase testCase) throws Exception
	{
		Cipher encryptor = newCipher(Cipher.ENCRYPT_MODE, testCase);
		Cipher decryptor = newCipher(Cipher.DECRYPT_MODE, testCase);

		assertEquals(testCase.transformation(), encryptor.getAlgorithm());
		// an uninitialized cipher would throw IllegalStateException here
		byte[] cipherText = encryptor.doFinal(PLAIN_TEXT);
		assertFalse(Arrays.equals(PLAIN_TEXT, cipherText));
		assertArrayEquals(PLAIN_TEXT, decryptor.doFinal(cipherText), testCase.transformation());

		if (testCase.paramSpec()instanceof IvParameterSpec ivParameterSpec)
		{
			assertArrayEquals(ivParameterSpec.getIV(), encryptor.getIV(),
				"the given IV must be used");
			assertArrayEquals(ivParameterSpec.getIV(), decryptor.getIV(),
				"the given IV must be used");
		}
	}
}
