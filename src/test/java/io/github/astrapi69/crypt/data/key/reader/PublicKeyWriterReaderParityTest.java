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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.data.key.writer.PublicKeyWriter;
import io.github.astrapi69.file.search.PathFinder;

/**
 * Parity tests for the {@link PublicKeyWriter} and {@link PublicKeyReader} pair, and regression
 * tests for issue #23.
 * <p>
 * The property is the one a writer and a reader owe each other: what one of them produces, the
 * other reads back as the same key. It held for rsa alone, because both entry points that take no
 * algorithm passed rsa to a key factory, so every other algorithm was written without complaint and
 * then refused on the way back in.
 */
class PublicKeyWriterReaderParityTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static PublicKey newPublicKey(final String algorithm) throws Exception
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
		return generator.generateKeyPair().getPublic();
	}

	/**
	 * A pem file written by the writer reads back through the reader that takes no algorithm,
	 * because a SubjectPublicKeyInfo names its own.
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
	void aPemPublicKeyIsReadBackWhateverItsAlgorithm(final String algorithm, @TempDir File tempDir)
		throws Exception
	{
		PublicKey publicKey = newPublicKey(algorithm);
		File file = new File(tempDir, algorithm + "-public.pem");
		PublicKeyWriter.writeInPemFormat(publicKey, file);

		PublicKey readBack = PublicKeyReader.readPemPublicKey(file);

		assertArrayEquals(publicKey.getEncoded(), readBack.getEncoded(),
			algorithm + " must be read back as the key that was written");
	}

	/**
	 * The der side of the same promise. The private key path survived issue #14 in der because
	 * getPrivateKey walks a list of algorithms; there is no such fallback here, so der broke too.
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
	void aDerPublicKeyIsReadBackWhateverItsAlgorithm(final String algorithm, @TempDir File tempDir)
		throws Exception
	{
		PublicKey publicKey = newPublicKey(algorithm);
		File file = new File(tempDir, algorithm + "-public.der");
		PublicKeyWriter.write(publicKey, file);

		assertArrayEquals(publicKey.getEncoded(), PublicKeyReader.readPublicKey(file).getEncoded(),
			algorithm + " must be read back from the file as the key that was written");
		assertArrayEquals(publicKey.getEncoded(),
			PublicKeyReader.readPublicKey(Files.readAllBytes(file.toPath())).getEncoded(),
			algorithm + " must be read back from the bytes as the key that was written");
	}

	/**
	 * Both encodings of one key are the same key, so the two files have to answer alike. A reader
	 * that resolved the algorithm on one path and assumed it on the other would show up here.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param tempDir
	 *            the directory the keys are written into
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519" })
	void thePemAndTheDerPathAgree(final String algorithm, @TempDir File tempDir) throws Exception
	{
		PublicKey publicKey = newPublicKey(algorithm);
		File pemFile = new File(tempDir, algorithm + ".pem");
		File derFile = new File(tempDir, algorithm + ".der");
		PublicKeyWriter.writeInPemFormat(publicKey, pemFile);
		PublicKeyWriter.write(publicKey, derFile);

		assertArrayEquals(PublicKeyReader.readPemPublicKey(pemFile).getEncoded(),
			PublicKeyReader.readPublicKey(derFile).getEncoded(),
			algorithm + " must read the same from pem as from der");
	}

	/**
	 * The algorithm identifier travels with the key, so what comes back names itself the way it
	 * went in.
	 * <p>
	 * The identifier is asserted and not the jca name, because the jca name says which provider
	 * built the object rather than what the file holds: bouncy castle calls an ec public key ECDSA
	 * and an edwards one Ed25519, where the jdk says EC and EdDSA for the same bytes.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param tempDir
	 *            the directory the key is written into
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519", "X25519" })
	void theAlgorithmSurvivesTheFile(final String algorithm, @TempDir File tempDir) throws Exception
	{
		PublicKey publicKey = newPublicKey(algorithm);
		File file = new File(tempDir, algorithm + ".pem");
		PublicKeyWriter.writeInPemFormat(publicKey, file);

		assertEquals(
			SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getAlgorithm().getAlgorithm(),
			SubjectPublicKeyInfo.getInstance(PublicKeyReader.readPemPublicKey(file).getEncoded())
				.getAlgorithm().getAlgorithm(),
			algorithm + " must come back under its own algorithm identifier");
	}

	/**
	 * Reading widely is not reading anything: a file that holds no public key is still refused.
	 *
	 * @param fileName
	 *            the name of the file in the pem test resource directory
	 */
	@ParameterizedTest
	@ValueSource(strings = { "certificate.pem", "private.pem", "csr-cert.pem" })
	void aPemFileThatHoldsNoPublicKeyIsRefused(final String fileName)
	{
		File file = new File(PathFinder.getSrcTestResourcesDir(), "pem/" + fileName);

		assertThrows(Exception.class, () -> PublicKeyReader.readPemPublicKey(file),
			fileName + " holds no public key and must not yield one");
	}

	/** A file that is not a key at all is refused rather than decoded into rubbish. */
	@Test
	void aFileThatIsNoKeyAtAllIsRefused(@TempDir File tempDir) throws Exception
	{
		File notAKey = new File(tempDir, "not-a-key.der");
		Files.writeString(notAKey.toPath(), "this file holds no key of any kind");

		assertThrows(Exception.class, () -> PublicKeyReader.readPublicKey(notAKey));
	}

	/**
	 * The other side of the refusal message: nothing was found at all, which is a different answer
	 * from having found the wrong thing and must read as one.
	 *
	 * @param tempDir
	 *            the directory the file is written into
	 * @throws Exception
	 *             if the file cannot be written
	 */
	@Test
	void aFileWithNoPemObjectAtAllIsRefusedAsHoldingNothing(@TempDir File tempDir) throws Exception
	{
		File notPem = new File(tempDir, "not-a-pem.txt");
		Files.writeString(notPem.toPath(), "there is no pem object anywhere in this file\n");

		InvalidKeySpecException refused = assertThrows(InvalidKeySpecException.class,
			() -> PublicKeyReader.readPemPublicKey(notPem));

		assertTrue(refused.getMessage().contains("nothing that the pem parser recognises"),
			"the message must say that nothing was found, but was: '" + refused.getMessage() + "'");
	}

	/** No file is not a file, and the reader says so before it opens anything. */
	@Test
	void aMissingFileIsRefusedOutright()
	{
		assertThrows(NullPointerException.class, () -> PemObjectReader.readPemPublicKey(null));
	}

	/**
	 * The rsa public key has a traditional header of its own, and a file carrying it is a public
	 * key file like any other.
	 */
	@Test
	void aTraditionalRsaPublicKeyFileIsReadToo() throws Exception
	{
		File file = new File(PathFinder.getSrcTestResourcesDir(), "pem/rsa-public-key.pem");

		PublicKey readBack = PublicKeyReader.readPemPublicKey(file);

		assertTrue(readBack.getAlgorithm().contains("RSA"),
			"the file says RSA PUBLIC KEY, but the key came back as " + readBack.getAlgorithm());
	}
}
