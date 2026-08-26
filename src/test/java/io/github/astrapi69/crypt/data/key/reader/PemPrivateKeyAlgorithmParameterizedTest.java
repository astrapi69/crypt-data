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
package io.github.astrapi69.crypt.data.key.reader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyFormat;
import io.github.astrapi69.crypt.data.key.writer.PrivateKeyWriter;
import io.github.astrapi69.file.search.PathFinder;

/**
 * Regression tests for issue #14: the entry points that read a pem private key without being told
 * an algorithm assumed rsa, so a valid ec, dsa or edwards key was refused and
 * {@link PrivateKeyReader#validatePrivateKey(File)} called it invalid.
 * <p>
 * Every key here is written by this library and read back by this library, so a failure is about
 * the pair of them and not about a fixture someone else produced.
 */
class PemPrivateKeyAlgorithmParameterizedTest
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

	private static File writeKey(final PrivateKey privateKey, final KeyFormat keyFormat,
		final File tempDir, final String name) throws Exception
	{
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		PrivateKeyWriter.write(privateKey, outputStream, KeyFileFormat.PEM, keyFormat);
		File file = new File(tempDir, name + ".pem");
		Files.write(file.toPath(), outputStream.toByteArray());
		return file;
	}

	/**
	 * A pkcs#8 file names its own algorithm in its algorithm identifier, so the reader never has to
	 * be told one - and must not assume one either.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param tempDir
	 *            the directory the key is written into
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519", "Ed448", "X25519", "DH" })
	void aPkcs8PemPrivateKeyIsReadWhateverItsAlgorithm(final String algorithm,
		@TempDir File tempDir) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);
		File file = writeKey(privateKey, KeyFormat.PKCS_8, tempDir, algorithm);

		PrivateKey readBack = PrivateKeyReader.readPemPrivateKey(file);

		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			algorithm + " must be read back as the key that was written");
	}

	/**
	 * The traditional form carries its algorithm in the header instead, which the reader has to
	 * take at its word rather than override with one of its own.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param tempDir
	 *            the directory the key is written into
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	// dsa is missing on purpose: what it writes traditionally is its private exponent alone, so
	// there is nothing to read back yet (issue #15)
	@ValueSource(strings = { "RSA", "EC" })
	void aTraditionalPemPrivateKeyIsReadWhateverItsAlgorithm(final String algorithm,
		@TempDir File tempDir) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);
		File file = writeKey(privateKey, KeyFormat.PKCS_1, tempDir, algorithm);

		PrivateKey readBack = PrivateKeyReader.readPemPrivateKey(file);

		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			algorithm + " must be read back as the key that was written");
	}

	/**
	 * The sharp end of issue #14: a caller that guards on this rejected every key that was not an
	 * rsa one, although the file was perfectly readable.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param tempDir
	 *            the directory the key is written into
	 * @throws Exception
	 *             if writing or validating fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519", "Ed448", "X25519", "DH" })
	void aValidKeyIsCalledValidWhateverItsAlgorithm(final String algorithm, @TempDir File tempDir)
		throws Exception
	{
		File file = writeKey(newPrivateKey(algorithm), KeyFormat.PKCS_8, tempDir, algorithm);

		assertTrue(PrivateKeyReader.validatePrivateKey(file),
			algorithm + " was written by this library and must be called a valid private key");
	}

	/**
	 * The general entry point picks the pem branch by looking at the file, so it inherits whatever
	 * that branch can read.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param tempDir
	 *            the directory the key is written into
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519" })
	void theGeneralReaderReadsAPemKeyWhateverItsAlgorithm(final String algorithm,
		@TempDir File tempDir) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);
		File file = writeKey(privateKey, KeyFormat.PKCS_8, tempDir, algorithm);

		PrivateKey readBack = PrivateKeyReader.readPrivateKey(file);

		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			algorithm + " must be read back as the key that was written");
	}

	/**
	 * Reading widely is not reading anything: a pem file that holds something other than a private
	 * key must still be refused, and the refusal has to name what was found there instead, so the
	 * caller is not left guessing which of its files was the wrong one.
	 *
	 * @param fileName
	 *            the name of the file in the pem test resource directory
	 * @param expectedFinding
	 *            what the message must say was found instead of a private key
	 * @throws Exception
	 *             if the file cannot be looked at at all
	 */
	@ParameterizedTest
	@CsvSource({ "certificate.pem, X509CertificateHolder", "public.pem, SubjectPublicKeyInfo",
			"csr-cert.pem, PKCS10CertificationRequest", "crl-cert.pem, X509CRLHolder",
			"encrypted-key.pem, PKCS8EncryptedPrivateKeyInfo" })
	void aPemFileThatHoldsNoPrivateKeyIsRefusedByName(final String fileName,
		final String expectedFinding) throws Exception
	{
		File file = new File(PathFinder.getSrcTestResourcesDir(), "pem/" + fileName);

		InvalidKeySpecException refused = assertThrows(InvalidKeySpecException.class,
			() -> PrivateKeyReader.readPemPrivateKey(file),
			fileName + " holds no readable private key and must not yield one");

		assertTrue(refused.getMessage().contains(file.getAbsolutePath()),
			"the message must name the file, but was: '" + refused.getMessage() + "'");
		assertTrue(refused.getMessage().contains(expectedFinding),
			"the message must say what was found instead, but was: '" + refused.getMessage() + "'");
		assertFalse(PrivateKeyReader.validatePrivateKey(file),
			fileName + " holds no readable private key and must not be called a valid one");
	}

	/**
	 * The other side of that message: nothing was found at all, which is a different answer from
	 * having found the wrong thing and must read as one.
	 *
	 * @param tempDir
	 *            the directory the file is written into
	 * @throws Exception
	 *             if the file cannot be written
	 */
	/**
	 * A pkcs#7 container is refused as well, but the pem parser gives up on it before this method
	 * gets to look, so what comes out is its failure rather than a named finding. It is here so
	 * that the input is covered rather than quietly dropped from the list above.
	 *
	 * @throws Exception
	 *             if the file cannot be looked at at all
	 */
	@Test
	void aPkcs7ContainerIsRefusedTooEvenThoughThePemParserGivesUpFirst() throws Exception
	{
		File file = new File(PathFinder.getSrcTestResourcesDir(), "pem/pkcs7.pem");

		assertThrows(Exception.class, () -> PrivateKeyReader.readPemPrivateKey(file));
		assertFalse(PrivateKeyReader.validatePrivateKey(file));
	}

	@Test
	void aFileWithNoPemObjectAtAllIsRefusedAsHoldingNothing(@TempDir File tempDir) throws Exception
	{
		File notPem = new File(tempDir, "not-a-pem.txt");
		Files.writeString(notPem.toPath(), "there is no pem object anywhere in this file\n");

		InvalidKeySpecException refused = assertThrows(InvalidKeySpecException.class,
			() -> PrivateKeyReader.readPemPrivateKey(notPem));

		assertTrue(refused.getMessage().contains("nothing that the pem parser recognises"),
			"the message must say that nothing was found, but was: '" + refused.getMessage() + "'");
	}
}
