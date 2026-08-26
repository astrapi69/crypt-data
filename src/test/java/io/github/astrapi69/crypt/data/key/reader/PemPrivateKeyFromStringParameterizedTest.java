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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyFormat;
import io.github.astrapi69.crypt.data.key.writer.PrivateKeyWriter;
import io.github.astrapi69.file.search.PathFinder;

/**
 * Regression tests for issue #19: {@link PrivateKeyReader#readPemPrivateKey(String)} assumed rsa
 * and refused the pem format its name promises.
 * <p>
 * The sibling of issue #14 in the overload that takes a string. Rsa passed there only because the
 * bouncy castle rsa key factory also accepts a raw pkcs#1 structure through a pkcs#8 key
 * specification, and that leniency is what hid the assumption for every other algorithm.
 */
class PemPrivateKeyFromStringParameterizedTest
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
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		PrivateKeyWriter.write(privateKey, outputStream, KeyFileFormat.PEM, keyFormat);
		return outputStream.toString(StandardCharsets.US_ASCII);
	}

	private static String bodyOf(final String pem)
	{
		return pem.replaceAll("-----[A-Z0-9 ]+-----", "").replaceAll("\\s", "");
	}

	/**
	 * A pkcs#8 body names its algorithm in its algorithm identifier, so the base64 alone is enough
	 * to build the key with, whatever it was made with.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519", "Ed448", "X25519", "DH" })
	void aPkcs8BodyIsReadWhateverItsAlgorithm(final String algorithm) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);

		PrivateKey readBack = PrivateKeyReader
			.readPemPrivateKey(bodyOf(pem(privateKey, KeyFormat.PKCS_8)));

		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			algorithm + " must be read back as the key that was written");
	}

	/**
	 * The method is called readPemPrivateKey and its parameter is documented as being in pem
	 * format, so a whole pem document has to be one of the things it takes.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519", "Ed448", "X25519", "DH" })
	void aWholePemDocumentIsReadWhateverItsAlgorithm(final String algorithm) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);

		PrivateKey readBack = PrivateKeyReader.readPemPrivateKey(pem(privateKey, KeyFormat.PKCS_8));

		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			algorithm + " must be read back as the key that was written");
	}

	/**
	 * The traditional form carries its algorithm in the header, so a whole document of it can be
	 * read as well - the header is the only thing that says what the bytes are.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC" })
	void aWholeTraditionalPemDocumentIsReadWhateverItsAlgorithm(final String algorithm)
		throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);

		PrivateKey readBack = PrivateKeyReader.readPemPrivateKey(pem(privateKey, KeyFormat.PKCS_1));

		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			algorithm + " must be read back as the key that was written");
	}

	/**
	 * A traditional rsa body without its header is what this method has always been handed, because
	 * readPemFileAsBase64 produces exactly that from a traditional rsa file. It keeps working.
	 *
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@Test
	void aTraditionalRsaBodyWithoutItsHeaderKeepsWorking() throws Exception
	{
		PrivateKey privateKey = newPrivateKey("RSA");

		PrivateKey readBack = PrivateKeyReader
			.readPemPrivateKey(bodyOf(pem(privateKey, KeyFormat.PKCS_1)));

		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded());
	}

	/**
	 * A traditional body of anything else, stripped of its header, says nothing about what it is.
	 * That cannot be read and must be refused with a message that says why rather than with the
	 * failure of whichever algorithm happened to be tried last.
	 *
	 * @param algorithm
	 *            the algorithm whose headerless traditional body is handed over
	 * @throws Exception
	 *             if writing fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "DSA", "EC" })
	void aHeaderlessTraditionalBodyOfAnythingElseIsRefusedWithAReason(final String algorithm)
		throws Exception
	{
		String headerless = bodyOf(pem(newPrivateKey(algorithm), KeyFormat.PKCS_1));

		InvalidKeySpecException refused = assertThrows(InvalidKeySpecException.class,
			() -> PrivateKeyReader.readPemPrivateKey(headerless));

		assertTrue(refused.getMessage().contains("no pem header"),
			"the message must say that nothing named the algorithm, but was: '"
				+ refused.getMessage() + "'");
	}

	/**
	 * Reading from a string and reading from a file are two ways to the same key, and must not
	 * disagree.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param tempDir
	 *            the directory the file is written into
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519" })
	void readingFromAStringAndFromAFileAgree(final String algorithm,
		@org.junit.jupiter.api.io.TempDir File tempDir) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);
		String pemText = pem(privateKey, KeyFormat.PKCS_8);
		File file = new File(tempDir, algorithm + ".pem");
		Files.writeString(file.toPath(), pemText, StandardCharsets.US_ASCII);

		assertArrayEquals(PrivateKeyReader.readPemPrivateKey(file).getEncoded(),
			PrivateKeyReader.readPemPrivateKey(pemText).getEncoded(),
			algorithm + " must read the same from the string as from the file");
	}

	/**
	 * A pem document that holds something other than a private key is refused, and the refusal says
	 * what was found instead.
	 *
	 * @param fileName
	 *            the name of the file in the pem test resource directory
	 * @param expectedFinding
	 *            what the message must say was found instead of a private key
	 * @throws Exception
	 *             if the file cannot be read
	 */
	@ParameterizedTest
	@CsvSource({ "certificate.pem, X509CertificateHolder", "public.pem, SubjectPublicKeyInfo",
			"csr-cert.pem, PKCS10CertificationRequest" })
	void aPemDocumentThatHoldsNoPrivateKeyIsRefusedByName(final String fileName,
		final String expectedFinding) throws Exception
	{
		String pemText = Files
			.readString(new File(PathFinder.getSrcTestResourcesDir(), "pem/" + fileName).toPath());

		InvalidKeySpecException refused = assertThrows(InvalidKeySpecException.class,
			() -> PrivateKeyReader.readPemPrivateKey(pemText));

		assertTrue(refused.getMessage().contains(expectedFinding),
			"the message must say what was found instead, but was: '" + refused.getMessage() + "'");
	}

	/**
	 * A text that opens like a pem document but holds rubbish is a parse failure rather than a
	 * wrong finding, and the message has to carry that reason instead of dropping it.
	 */
	@Test
	void aMalformedPemDocumentIsRefusedWithTheParseFailureAsTheReason()
	{
		String malformed = """
			-----BEGIN CERTIFICATE-----
			bm90IGFuIGFzbjEgc3RydWN0dXJlIGF0IGFsbA==
			-----END CERTIFICATE-----
			""";

		InvalidKeySpecException refused = assertThrows(InvalidKeySpecException.class,
			() -> PrivateKeyReader.readPemPrivateKey(malformed));

		assertTrue(refused.getMessage().contains("could not be parsed"),
			"the message must say the text could not be parsed, but was: '" + refused.getMessage()
				+ "'");
		assertTrue(refused.getCause() instanceof java.io.IOException,
			"the parse failure must travel with it as the cause");
	}

	/** Nothing is not a key, and says so before anything tries to decode it. */
	@Test
	void aMissingStringIsRefusedOutright()
	{
		assertThrows(NullPointerException.class,
			() -> PrivateKeyReader.readPemPrivateKey((String)null));
	}
}
