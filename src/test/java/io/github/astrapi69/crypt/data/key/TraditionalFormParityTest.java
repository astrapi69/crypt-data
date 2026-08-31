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
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

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

	private static PrivateKey newPrivateKey(final String algorithm) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm,
			BouncyCastleProvider.PROVIDER_NAME);
		if ("RSA".equals(algorithm) || "DSA".equals(algorithm))
		{
			generator.initialize(2048);
		}
		if ("DH".equals(algorithm))
		{
			generator.initialize(1024);
		}
		return generator.generateKeyPair().getPrivate();
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
	 * The question the caller could not ask. Every algorithm this library can generate is answered,
	 * the three that no test used to write among them.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param expected
	 *            whether that algorithm has a traditional form of its own
	 * @throws Exception
	 *             if key generation fails
	 */
	@ParameterizedTest
	@CsvSource({ "RSA, true", "DSA, true", "EC, true", "Ed25519, false", "Ed448, false",
			"X25519, false", "X448, false", "DH, false", "ML-KEM-768, false", "ML-DSA-65, false" })
	void everyAlgorithmSaysWhetherItHasATraditionalForm(final String algorithm,
		final boolean expected) throws Exception
	{
		assertEquals(expected, PrivateKeyExtensions.hasTraditionalForm(newPrivateKey(algorithm)),
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
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519", "Ed448", "X25519", "X448", "DH",
			"ML-KEM-768", "ML-DSA-65" })
	void theAnswerIsTrueExactlyWhenTheTwoFormatsDiffer(final String algorithm) throws Exception
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
	 * The three algorithms no test used to write. They work; that was never asserted.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param keyFileFormat
	 *            the file format to write in
	 * @param keyFormat
	 *            the key format to ask for
	 * @throws Exception
	 *             if key generation or writing fails
	 */
	@ParameterizedTest
	@CsvSource({ "X448, PEM, PKCS_8", "X448, PEM, PKCS_1", "X448, DER, PKCS_8", "X448, DER, PKCS_1",
			"ML-KEM-768, PEM, PKCS_8", "ML-KEM-768, PEM, PKCS_1", "ML-KEM-768, DER, PKCS_8",
			"ML-KEM-768, DER, PKCS_1", "ML-DSA-65, PEM, PKCS_8", "ML-DSA-65, PEM, PKCS_1",
			"ML-DSA-65, DER, PKCS_8", "ML-DSA-65, DER, PKCS_1" })
	void theAlgorithmsThatWereNeverWrittenAreWrittenNow(final String algorithm,
		final KeyFileFormat keyFileFormat, final KeyFormat keyFormat) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		PrivateKeyWriter.write(privateKey, out, keyFileFormat, keyFormat);
		byte[] written = out.toByteArray();

		if (keyFileFormat == KeyFileFormat.DER)
		{
			assertArrayEquals(privateKey.getEncoded(), written,
				algorithm + " as der is the encoding unchanged, whatever key format is named");
			return;
		}
		String text = new String(written, StandardCharsets.US_ASCII);
		assertTrue(text.startsWith("-----BEGIN PRIVATE KEY-----"),
			algorithm + " has no traditional form, so both formats carry the pkcs#8 header");
		assertArrayEquals(privateKey.getEncoded(), bodyOf(text));
	}

	/** Nothing is not a key. */
	@org.junit.jupiter.api.Test
	void aMissingKeyIsRefusedOutright()
	{
		assertThrows(NullPointerException.class,
			() -> PrivateKeyExtensions.hasTraditionalForm(null));
	}
}
