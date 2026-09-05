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
package io.github.astrapi69.crypt.data.key.writer;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyFormat;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;

/**
 * Asking for {@link KeyFormat#PKCS_1} used to be answered with the PKCS#8 file for every algorithm
 * that has no traditional form of its own - the caller was given a format it did not request and
 * was told nothing (issue #42).
 * <p>
 * The expectation is derived from {@link PrivateKeyExtensions#hasTraditionalForm(PrivateKey)} and
 * the algorithms from the enum, rather than from a list written here, so an algorithm added later
 * joins these tests by existing. A second list of names is what went wrong everywhere else this
 * question was answered.
 */
class PrivateKeyWriterRefusesPkcs1Test
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	static Stream<KeyPairGeneratorAlgorithm> generatableAlgorithms()
	{
		return Arrays.stream(KeyPairGeneratorAlgorithm.values())
			.filter(PrivateKeyWriterRefusesPkcs1Test::canGenerate);
	}

	private static boolean canGenerate(final KeyPairGeneratorAlgorithm algorithm)
	{
		try
		{
			newPrivateKey(algorithm);
			return true;
		}
		catch (Exception cannotGenerate)
		{
			return false;
		}
	}

	private static PrivateKey newPrivateKey(final KeyPairGeneratorAlgorithm algorithm)
		throws Exception
	{
		String name = algorithm.getAlgorithm();
		KeyPairGenerator generator = KeyPairGenerator.getInstance(name,
			BouncyCastleProvider.PROVIDER_NAME);
		if ("RSA".equals(name) || "DSA".equals(name) || "RSASSA-PSS".equals(name))
		{
			generator.initialize(2048);
		}
		if ("DiffieHellman".equals(name) || "DH".equals(name))
		{
			generator.initialize(1024);
		}
		return generator.generateKeyPair().getPrivate();
	}

	private static void writePem(final PrivateKey privateKey, final KeyFormat keyFormat)
		throws Exception
	{
		PrivateKeyWriter.write(privateKey, new ByteArrayOutputStream(), KeyFileFormat.PEM,
			keyFormat);
	}

	@ParameterizedTest(name = "{0} as PEM/PKCS#1: written when it has a traditional form, refused when it has not")
	@MethodSource("generatableAlgorithms")
	@DisplayName("PKCS#1 is written or refused, never silently answered with PKCS#8")
	void pkcs1IsWrittenOrRefused(final KeyPairGeneratorAlgorithm algorithm) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);

		if (PrivateKeyExtensions.hasTraditionalForm(privateKey))
		{
			assertDoesNotThrow(() -> writePem(privateKey, KeyFormat.PKCS_1),
				algorithm + " has a traditional form and must still be written as PKCS#1");
			return;
		}
		InvalidKeySpecException refused = assertThrows(InvalidKeySpecException.class,
			() -> writePem(privateKey, KeyFormat.PKCS_1),
			algorithm + " has no traditional form, so asking for PKCS#1 must be refused");
		assertTrue(refused.getMessage().contains(privateKey.getAlgorithm()),
			"the refusal must name the algorithm, was: " + refused.getMessage());
	}

	/**
	 * The refusal is about the traditional format, not about the key: PKCS#8 stays writable for
	 * every algorithm, including the ones that have nothing else
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if generating the key fails
	 */
	@ParameterizedTest(name = "{0} is still written as PKCS#8")
	@MethodSource("generatableAlgorithms")
	void pkcs8StaysWritableForEveryAlgorithm(final KeyPairGeneratorAlgorithm algorithm)
		throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);

		assertDoesNotThrow(() -> writePem(privateKey, KeyFormat.PKCS_8));
		assertDoesNotThrow(() -> writePem(privateKey, null));
	}

	/**
	 * DER ignores the key format for every algorithm and is deliberately left as it is (issue #42),
	 * so naming PKCS#1 there must keep working rather than start throwing
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if generating the key fails
	 */
	@ParameterizedTest(name = "{0} as DER with PKCS#1 named is untouched")
	@MethodSource("generatableAlgorithms")
	void derIgnoresTheKeyFormatAsBefore(final KeyPairGeneratorAlgorithm algorithm) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);
		ByteArrayOutputStream written = new ByteArrayOutputStream();

		assertDoesNotThrow(
			() -> PrivateKeyWriter.write(privateKey, written, KeyFileFormat.DER, KeyFormat.PKCS_1));
		assertEquals(privateKey.getEncoded().length, written.toByteArray().length,
			algorithm + " as DER must stay the encoded key");
	}
}
