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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyFormat;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;

/**
 * Regression tests for issue #12: {@link PrivateKeyWriter} wrote PKCS#1 when PKCS#8 was asked for.
 * <p>
 * The property under test is the one the option promises: what the caller names is what lands in
 * the file, and the key reads back unchanged.
 */
class PrivateKeyWriterPkcs8Test
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static PrivateKey newPrivateKey(final String algorithm, final int size) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm,
			BouncyCastleProvider.PROVIDER_NAME);
		if (size > 0)
		{
			generator.initialize(size);
		}
		return generator.generateKeyPair().getPrivate();
	}

	private static byte[] bodyOf(final String pem)
	{
		return Base64.getDecoder()
			.decode(pem.replaceAll("-----[A-Z0-9 ]+-----", "").replaceAll("\\s", ""));
	}

	private static String pem(final PrivateKey privateKey, final KeyFormat keyFormat)
		throws Exception
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		PrivateKeyWriter.write(privateKey, out, KeyFileFormat.PEM, keyFormat);
		return out.toString(StandardCharsets.US_ASCII);
	}

	/**
	 * PKCS#8 means the wrapper, under the header that names it, for every algorithm - including the
	 * ones that have a traditional form of their own.
	 */
	@ParameterizedTest
	@CsvSource({ "RSA, 2048", "EC, 0", "DSA, 2048", "Ed25519, 0" })
	void askingForPkcs8WritesPkcs8(final String algorithm, final int size) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm, size);

		String written = pem(privateKey, KeyFormat.PKCS_8);

		assertTrue(written.startsWith("-----BEGIN PRIVATE KEY-----"),
			algorithm + " must be written under the PKCS#8 header, but the file began '"
				+ written.lines().findFirst().orElse("") + "'");
		assertArrayEquals(privateKey.getEncoded(), bodyOf(written),
			algorithm + " must be written as its PKCS#8 encoding, not with the wrapper stripped");
	}

	/** The traditional form is unchanged: that branch was never the defective one. */
	@ParameterizedTest
	@CsvSource({ "RSA, 2048, RSA PRIVATE KEY", "EC, 0, EC PRIVATE KEY",
			"DSA, 2048, DSA PRIVATE KEY" })
	void askingForPkcs1StillWritesTheTraditionalForm(final String algorithm, final int size,
		final String expectedHeader) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm, size);

		String written = pem(privateKey, KeyFormat.PKCS_1);

		assertTrue(written.startsWith("-----BEGIN " + expectedHeader + "-----"),
			"the file began '" + written.lines().findFirst().orElse("") + "'");
		assertArrayEquals(PrivateKeyExtensions.toPKCS1Format(privateKey), bodyOf(written));
	}

	/**
	 * No format named is the same as PKCS#8, which is what the writer already promises by treating
	 * a null key format like that constant.
	 */
	@ParameterizedTest
	@CsvSource({ "RSA, 2048", "Ed25519, 0" })
	void namingNoFormatMeansPkcs8(final String algorithm, final int size) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm, size);

		assertEquals(pem(privateKey, KeyFormat.PKCS_8), pem(privateKey, null));
	}

	/** What matters in the end: the file reads back as the key that was written. */
	@ParameterizedTest
	@CsvSource({ "RSA, 2048", "EC, 0", "DSA, 2048" })
	void aKeyWrittenAsPkcs8ReadsBackUnchanged(final String algorithm, final int size,
		@TempDir File tempDir) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm, size);
		File file = new File(tempDir, "private.pem");
		Files.writeString(file.toPath(), pem(privateKey, KeyFormat.PKCS_8),
			StandardCharsets.US_ASCII);

		PrivateKey readBack = PrivateKeyReader.readPemPrivateKey(file, algorithm);

		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			algorithm + " must come back as the same key");
	}

	/**
	 * The mislabelled fallback: a key with no traditional form of its own was written under the
	 * PKCS#8 header with the wrapper stripped, so the file was readable as neither format.
	 */
	@ParameterizedTest
	@CsvSource({ "Ed25519", "Ed448" })
	void aKeyWithNoTraditionalFormIsNotLabelledPkcs8WhileBeingPkcs1(final String algorithm)
		throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm, 0);

		String written = PrivateKeyExtensions.toPemFormat(privateKey);

		assertTrue(
			!written.startsWith("-----BEGIN PRIVATE KEY-----")
				|| java.util.Arrays.equals(privateKey.getEncoded(), bodyOf(written)),
			"the PRIVATE KEY header means PKCS#8, so a file carrying it must hold the PKCS#8 "
				+ "encoding, but " + algorithm + " was written as '"
				+ written.lines().findFirst().orElse("") + "' over stripped content");
	}
}
