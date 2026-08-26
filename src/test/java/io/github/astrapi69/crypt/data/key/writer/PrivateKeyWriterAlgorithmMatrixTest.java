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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyFormat;
import io.github.astrapi69.crypt.api.key.PemType;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.crypt.data.key.reader.PemObjectReader;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;

/**
 * Parameterized tests for
 * {@link PrivateKeyWriter#write(PrivateKey, java.io.OutputStream, KeyFileFormat, KeyFormat)} across
 * every key algorithm the writer can be handed, not only the rsa key that
 * {@link PrivateKeyWriterFormatParameterizedTest} drives.
 * <p>
 * Issue #12 was invisible from a single algorithm: the header the writer chose came from the bytes
 * rather than from the key, so it was right for rsa and wrong for everything else. The cross
 * product of algorithm, file format and key format is what makes that class of defect visible.
 */
class PrivateKeyWriterAlgorithmMatrixTest
{

	/**
	 * One key algorithm with the pem type its traditional form carries. Algorithms with no
	 * traditional form of their own carry the pkcs#8 type, because that is what they keep.
	 *
	 * @param algorithm
	 *            the algorithm name the key pair generator is asked for
	 * @param keySize
	 *            the key size to initialize with, or 0 to leave the default
	 * @param traditionalPemType
	 *            the pem type the traditional form of this algorithm is written under
	 */
	record AlgorithmUnderTest(String algorithm, int keySize, String traditionalPemType) {
		@Override
		public String toString()
		{
			return algorithm;
		}
	}

	/**
	 * One combination of algorithm, file format and key format with the pem type it must produce
	 *
	 * @param keyAlgorithm
	 *            the algorithm under test
	 * @param fileFormat
	 *            the file format to write in
	 * @param keyFormat
	 *            the key format to write in, may be null
	 * @param expectedPemType
	 *            the pem type the output must carry, or null when der output is expected
	 */
	record WriteCase(AlgorithmUnderTest keyAlgorithm, KeyFileFormat fileFormat, KeyFormat keyFormat,
		String expectedPemType) {
		@Override
		public String toString()
		{
			return keyAlgorithm + " written as " + fileFormat + " with "
				+ (keyFormat == null ? "no key format named" : keyFormat) + " gives "
				+ (expectedPemType == null ? "der" : "'" + expectedPemType + "'");
		}
	}

	private static final List<AlgorithmUnderTest> ALGORITHMS = List.of(
		new AlgorithmUnderTest("RSA", 2048, PemType.RSA_PRIVATE_KEY.getName()),
		new AlgorithmUnderTest("DSA", 2048, PemType.DSA_PRIVATE_KEY.getName()),
		new AlgorithmUnderTest("EC", 0, PemType.EC_PRIVATE_KEY.getName()),
		new AlgorithmUnderTest("Ed25519", 0, PemType.PRIVATE_KEY.getName()),
		new AlgorithmUnderTest("Ed448", 0, PemType.PRIVATE_KEY.getName()),
		new AlgorithmUnderTest("X25519", 0, PemType.PRIVATE_KEY.getName()),
		new AlgorithmUnderTest("DH", 1024, PemType.PRIVATE_KEY.getName()));

	/** generated once per algorithm, because the matrix asks for the same key many times over */
	private static final Map<String, PrivateKey> KEYS = new LinkedHashMap<>();

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static PrivateKey keyOf(final AlgorithmUnderTest keyAlgorithm)
	{
		return KEYS.computeIfAbsent(keyAlgorithm.algorithm(), algorithm -> {
			try
			{
				KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm,
					BouncyCastleProvider.PROVIDER_NAME);
				if (keyAlgorithm.keySize() > 0)
				{
					generator.initialize(keyAlgorithm.keySize());
				}
				return generator.generateKeyPair().getPrivate();
			}
			catch (Exception cannotGenerate)
			{
				throw new IllegalStateException(
					"no key pair for algorithm '" + algorithm + "' could be generated",
					cannotGenerate);
			}
		});
	}

	private static byte[] written(final PrivateKey privateKey, final KeyFileFormat fileFormat,
		final KeyFormat keyFormat) throws IOException
	{
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		PrivateKeyWriter.write(privateKey, outputStream, fileFormat, keyFormat);
		return outputStream.toByteArray();
	}

	static Stream<WriteCase> writeCases()
	{
		return ALGORITHMS.stream().flatMap(keyAlgorithm -> Stream.of(
			// pem says what the key format names, for every algorithm
			new WriteCase(keyAlgorithm, KeyFileFormat.PEM, KeyFormat.PKCS_8,
				PemType.PRIVATE_KEY.getName()),
			new WriteCase(keyAlgorithm, KeyFileFormat.PEM, null, PemType.PRIVATE_KEY.getName()),
			new WriteCase(keyAlgorithm, KeyFileFormat.PEM, KeyFormat.PKCS_1,
				keyAlgorithm.traditionalPemType()),
			// a key format the writer does not know falls through to der
			new WriteCase(keyAlgorithm, KeyFileFormat.PEM, KeyFormat.UNKNOWN, null),
			// every other file format is der, whatever key format travels with it
			new WriteCase(keyAlgorithm, KeyFileFormat.DER, KeyFormat.PKCS_8, null),
			new WriteCase(keyAlgorithm, KeyFileFormat.DER, KeyFormat.PKCS_1, null),
			new WriteCase(keyAlgorithm, KeyFileFormat.P7B, null, null),
			new WriteCase(keyAlgorithm, KeyFileFormat.UNKNOWN, KeyFormat.PKCS_1, null)));
	}

	/**
	 * The property the options promise: what the caller names is what the file says it is, and the
	 * body underneath matches that name rather than some other encoding.
	 *
	 * @param testCase
	 *            the combination under test
	 * @throws Exception
	 *             if writing or parsing back fails
	 */
	@ParameterizedTest
	@MethodSource("writeCases")
	void whatTheCallerNamesIsWhatLandsInTheFile(final WriteCase testCase) throws Exception
	{
		PrivateKey privateKey = keyOf(testCase.keyAlgorithm());

		byte[] writtenBytes = written(privateKey, testCase.fileFormat(), testCase.keyFormat());

		if (testCase.expectedPemType() == null)
		{
			assertArrayEquals(privateKey.getEncoded(), writtenBytes,
				testCase + " must be the der encoding unchanged");
			return;
		}
		String pem = new String(writtenBytes, StandardCharsets.US_ASCII);
		PemObject pemObject = PemObjectReader.getPemObject(pem);
		assertEquals(testCase.expectedPemType(), pemObject.getType(),
			testCase + ", but the header said '" + pemObject.getType() + "'");
		byte[] expectedContent = PemType.PRIVATE_KEY.getName().equals(testCase.expectedPemType())
			? privateKey.getEncoded()
			: PrivateKeyExtensions.toPKCS1Format(privateKey);
		assertArrayEquals(expectedContent, pemObject.getContent(),
			testCase + ", and the body has to be the encoding that header names");
	}

	/**
	 * Outside pem the key format has nothing to select, so naming one must not change the bytes.
	 * Only the pem branch reads it, and a der file that differed by key format would mean the
	 * fall-through had picked up a branch of its own.
	 *
	 * @param keyAlgorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if writing fails
	 */
	@ParameterizedTest
	@MethodSource("algorithms")
	void namingAKeyFormatChangesNothingOutsidePem(final AlgorithmUnderTest keyAlgorithm)
		throws Exception
	{
		PrivateKey privateKey = keyOf(keyAlgorithm);

		byte[] asPkcs8 = written(privateKey, KeyFileFormat.DER, KeyFormat.PKCS_8);
		byte[] asPkcs1 = written(privateKey, KeyFileFormat.DER, KeyFormat.PKCS_1);
		byte[] unnamed = written(privateKey, KeyFileFormat.DER, null);

		assertArrayEquals(asPkcs8, asPkcs1,
			keyAlgorithm + " as der must not depend on the key format");
		assertArrayEquals(asPkcs8, unnamed);
		assertArrayEquals(privateKey.getEncoded(), asPkcs8);
	}

	static Stream<AlgorithmUnderTest> algorithms()
	{
		return ALGORITHMS.stream();
	}

	/**
	 * A pem file is only readable elsewhere if it is wrapped the way rfc 7468 asks: base64 broken
	 * at 64 characters, one begin line and one end line that name the same type.
	 *
	 * @param keyAlgorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if writing fails
	 */
	@ParameterizedTest
	@MethodSource("algorithms")
	void everyPemFileIsWrappedTheWayOtherToolsExpect(final AlgorithmUnderTest keyAlgorithm)
		throws Exception
	{
		for (KeyFormat keyFormat : List.of(KeyFormat.PKCS_8, KeyFormat.PKCS_1))
		{
			String pem = new String(written(keyOf(keyAlgorithm), KeyFileFormat.PEM, keyFormat),
				StandardCharsets.US_ASCII);
			List<String> lines = pem.lines().toList();
			String type = keyFormat == KeyFormat.PKCS_8
				? PemType.PRIVATE_KEY.getName()
				: keyAlgorithm.traditionalPemType();

			assertEquals("-----BEGIN " + type + "-----", lines.get(0), keyAlgorithm + " as "
				+ keyFormat + " must open with the header that names what follows");
			assertEquals("-----END " + type + "-----", lines.get(lines.size() - 1),
				keyAlgorithm + " as " + keyFormat + " must close with the matching footer");
			assertTrue(lines.size() > 2, keyAlgorithm + " as " + keyFormat + " has no body");
			List<String> body = lines.subList(1, lines.size() - 1);
			assertTrue(body.stream().allMatch(line -> line.length() <= 64),
				keyAlgorithm + " as " + keyFormat
					+ " must break its base64 at 64 characters, but a line was "
					+ body.stream().mapToInt(String::length).max().orElse(0) + " long");
			assertTrue(body.subList(0, body.size() - 1).stream().allMatch(l -> l.length() == 64),
				keyAlgorithm + " as " + keyFormat + " must fill every line but the last");
		}
	}

	/**
	 * The only thing that finally matters about a written key: it comes back, as the same bytes and
	 * under the same algorithm.
	 * <p>
	 * The reader is handed the algorithm here although a pkcs#8 file names its own. The entry point
	 * that takes no algorithm assumes rsa and refuses everything else (issue #14), and the writer
	 * is what this class is about, so it is told rather than left to guess.
	 *
	 * @param keyAlgorithm
	 *            the algorithm under test
	 * @param tempDir
	 *            the directory the file is written into
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@MethodSource("algorithms")
	void aKeyWrittenAsPkcs8ComesBackAsTheSameKey(final AlgorithmUnderTest keyAlgorithm,
		@TempDir File tempDir) throws Exception
	{
		PrivateKey privateKey = keyOf(keyAlgorithm);
		File file = new File(tempDir, keyAlgorithm.algorithm() + "-private.pem");
		Files.write(file.toPath(), written(privateKey, KeyFileFormat.PEM, KeyFormat.PKCS_8));

		PrivateKey readBack = PrivateKeyReader.readPemPrivateKey(file, privateKey.getAlgorithm());

		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			keyAlgorithm + " must read back as the key that was written");
		// the algorithm identifier, not the jca name: bouncy castle calls an edwards key Ed25519
		// and the jdk key factory calls the same key EdDSA, so the name says which provider built
		// the object rather than what the file holds. The object identifier is the file's own word
		assertEquals(PrivateKeyInfo.getInstance(privateKey.getEncoded()).getPrivateKeyAlgorithm(),
			PrivateKeyInfo.getInstance(readBack.getEncoded()).getPrivateKeyAlgorithm(),
			keyAlgorithm + " must keep its algorithm across the file");
	}

	/**
	 * The traditional form has to survive the round trip as well, for the algorithms that have one.
	 * Before issue #12 an ec key went out under an rsa header, which is a file no reader can make
	 * sense of - reading it back is what proves the header now belongs to the key.
	 *
	 * @param algorithm
	 *            the algorithm whose traditional form is written
	 * @param keySize
	 *            the key size to generate with, 0 for the default
	 * @param tempDir
	 *            the directory the file is written into
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@MethodSource("algorithmsWithATraditionalForm")
	void aKeyWrittenTraditionallyComesBackAsTheSameKey(final String algorithm, final int keySize,
		@TempDir File tempDir) throws Exception
	{
		AlgorithmUnderTest keyAlgorithm = ALGORITHMS.stream()
			.filter(candidate -> candidate.algorithm().equals(algorithm)).findFirst().orElseThrow();
		PrivateKey privateKey = keyOf(keyAlgorithm);
		File file = new File(tempDir, algorithm + "-traditional.pem");
		Files.write(file.toPath(), written(privateKey, KeyFileFormat.PEM, KeyFormat.PKCS_1));

		// the traditional form has no algorithm identifier of its own, so it is read the way any
		// other tool reads it: through the pem parser, which takes the header at its word
		Object parsed = PemObjectReader.readPemKeyObject(file);
		PrivateKey readBack = new JcaPEMKeyConverter()
			.setProvider(BouncyCastleProvider.PROVIDER_NAME).getKeyPair((PEMKeyPair)parsed)
			.getPrivate();

		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			algorithm + " must read back as the key that was written");
	}

	static Stream<Arguments> algorithmsWithATraditionalForm()
	{
		// dsa belongs here and is missing on purpose: what it writes under DSA PRIVATE KEY is the
		// private exponent alone, without p, q and g, so nothing can read it back (issue #15)
		return Stream.of(Arguments.of("RSA", 2048), Arguments.of("EC", 0));
	}

	/**
	 * Both arguments are required, and the writer says so before it writes a partial file rather
	 * than after.
	 */
	@ParameterizedTest
	@MethodSource("algorithms")
	void neitherTheKeyNorTheStreamMayBeMissing(final AlgorithmUnderTest keyAlgorithm)
	{
		assertThrows(NullPointerException.class, () -> PrivateKeyWriter.write(keyOf(keyAlgorithm),
			null, KeyFileFormat.PEM, KeyFormat.PKCS_8));
		assertThrows(NullPointerException.class, () -> PrivateKeyWriter.write(null,
			new ByteArrayOutputStream(), KeyFileFormat.PEM, KeyFormat.PKCS_8));
	}
}
