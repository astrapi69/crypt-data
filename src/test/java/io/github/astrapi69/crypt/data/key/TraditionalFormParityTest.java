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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyFormat;
import io.github.astrapi69.crypt.data.key.writer.PrivateKeyWriter;

/**
 * Tests for issue #40: asking for PKCS#1 yielded PKCS#8 for every key with no traditional form of
 * its own, byte for byte, without saying so.
 * <p>
 * The bytes were right - a key with no traditional form has no wrapper to strip, and writing PKCS#1
 * content under a PRIVATE KEY header is the defect #12 fixed. The silence was not: the only way to
 * find out was to write the key twice and compare.
 * <p>
 * {@link PrivateKeyExtensions#hasTraditionalForm(PrivateKey)} makes it answerable before the fact,
 * and these tests tie the answer to what the writer actually does - so the two cannot drift apart.
 * The three algorithms that were never written by any test are driven here too: X448, ML-KEM and
 * ML-DSA.
 */
class TraditionalFormParityTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}


	private static String pem(final PrivateKey privateKey, final KeyFormat keyFormat)
		throws Exception
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		PrivateKeyWriter.write(privateKey, out, KeyFileFormat.PEM, keyFormat);
		return out.toString(StandardCharsets.US_ASCII);
	}

	private static byte[] bodyOf(final String text)
	{
		return Base64.getDecoder()
			.decode(text.replaceAll("-----[A-Z0-9 ]+-----", "").replaceAll("\\s", ""));
	}

	/**
	 * Every algorithm this library names, taken from the enum rather than from a list written by
	 * hand, so one added later joins these tests by existing.
	 *
	 * @return the algorithms that can generate a key pair here
	 */
	static Stream<KeyPairGeneratorAlgorithm> generatableAlgorithms()
	{
		return Arrays.stream(KeyPairGeneratorAlgorithm.values())
			.filter(TraditionalFormParityTest::canGenerate);
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

	/**
	 * The two the enum names that cannot generate a key pair here, asserted so that neither becomes
	 * three without anyone noticing.
	 * <p>
	 * XDH is the umbrella name for the montgomery curves and needs a parameter spec to say which;
	 * UNKNOWN is the enum's placeholder and is not an algorithm at all. Everything else is driven
	 * by the tests below.
	 */
	@Test
	void exactlyTwoOfTheNamedAlgorithmsCannotGenerateAKeyPair()
	{
		List<String> cannot = Arrays.stream(KeyPairGeneratorAlgorithm.values())
			.filter(algorithm -> !canGenerate(algorithm)).map(Enum::name).sorted().toList();

		assertEquals(List.of("UNKNOWN", "XDH"), cannot,
			"a newly named algorithm must be driven by these tests, not quietly join this list");
	}

	/**
	 * The question the caller could not ask, for every algorithm that can be generated.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if key generation fails
	 */
	@ParameterizedTest
	@MethodSource("generatableAlgorithms")
	void everyAlgorithmSaysWhetherItHasATraditionalForm(final KeyPairGeneratorAlgorithm algorithm)
		throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);
		boolean expected = privateKey instanceof java.security.interfaces.RSAPrivateKey
			|| privateKey instanceof java.security.interfaces.DSAPrivateKey
			|| privateKey instanceof java.security.interfaces.ECPrivateKey;

		assertEquals(expected, PrivateKeyExtensions.hasTraditionalForm(privateKey),
			algorithm + " must answer whether it has a traditional form of its own");
	}

	/**
	 * The property that keeps the answer honest: it says yes exactly when asking for PKCS#1 gives
	 * something other than PKCS#8. A query that drifted from the writer would be worse than none.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if key generation or writing fails
	 */
	@ParameterizedTest
	@MethodSource("generatableAlgorithms")
	void theAnswerIsTrueExactlyWhenTheTwoFormatsDiffer(final KeyPairGeneratorAlgorithm algorithm)
		throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);

		String traditional = pem(privateKey, KeyFormat.PKCS_1);
		String pkcs8 = pem(privateKey, KeyFormat.PKCS_8);

		if (PrivateKeyExtensions.hasTraditionalForm(privateKey))
		{
			assertNotEquals(pkcs8, traditional,
				algorithm + " says it has a traditional form, so the two must differ");
			assertFalse(traditional.startsWith("-----BEGIN PRIVATE KEY-----"),
				algorithm + " must carry its own header, but was: "
					+ traditional.lines().findFirst().orElse(""));
		}
		else
		{
			assertEquals(pkcs8, traditional,
				algorithm + " has no traditional form, so asking for one gives the pkcs#8 file");
			assertArrayEquals(privateKey.getEncoded(), bodyOf(traditional),
				algorithm + " must hold its pkcs#8 encoding, not a stripped wrapper");
		}
	}

	/**
	 * The whole cross product, for every algorithm: both file formats and both key formats. Der
	 * ignores the key format by design, pem carries what the algorithm has.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if key generation or writing fails
	 */
	@ParameterizedTest
	@MethodSource("generatableAlgorithms")
	void everyCombinationOfFileFormatAndKeyFormatIsWritten(
		final KeyPairGeneratorAlgorithm algorithm) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);
		boolean traditional = PrivateKeyExtensions.hasTraditionalForm(privateKey);

		for (KeyFormat keyFormat : new KeyFormat[] { KeyFormat.PKCS_8, KeyFormat.PKCS_1 })
		{
			ByteArrayOutputStream der = new ByteArrayOutputStream();
			PrivateKeyWriter.write(privateKey, der, KeyFileFormat.DER, keyFormat);
			assertArrayEquals(privateKey.getEncoded(), der.toByteArray(),
				algorithm + " as der with " + keyFormat + " is the encoding unchanged");

			String text = pem(privateKey, keyFormat);
			boolean pkcs8Header = text.startsWith("-----BEGIN PRIVATE KEY-----");
			if (keyFormat == KeyFormat.PKCS_8 || !traditional)
			{
				assertTrue(pkcs8Header,
					algorithm + " with " + keyFormat + " must carry the pkcs#8 header, but was: "
						+ text.lines().findFirst().orElse(""));
				assertArrayEquals(privateKey.getEncoded(), bodyOf(text));
			}
			else
			{
				assertFalse(pkcs8Header,
					algorithm + " with " + keyFormat
						+ " must carry its own traditional header, but was: "
						+ text.lines().findFirst().orElse(""));
			}
		}
	}

	/** Nothing is not a key. */
	@Test
	void aMissingKeyIsRefusedOutright()
	{
		assertThrows(NullPointerException.class,
			() -> PrivateKeyExtensions.hasTraditionalForm(null));
	}
}
