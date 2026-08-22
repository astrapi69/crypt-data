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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Optional;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.file.search.PathFinder;

/**
 * Parameterized tests for {@link PemObjectReader#readPemPrivateKey(File, String)} and the non-null
 * contract of the {@link PemObjectReader} methods
 */
class PemObjectReaderPrivateKeyParameterizedTest
{

	private static File pemDir;

	/**
	 * One pem file read with a password
	 *
	 * @param fileName
	 *            the name of the file in the pem test resource directory
	 * @param password
	 *            the password
	 * @param expectedPresent
	 *            whether a private key is expected, i.e. whether the file holds a traditional
	 *            OpenSSL encrypted key pair
	 * @param expectedAlgorithm
	 *            the algorithm of the expected private key, ignored if none is expected
	 */
	record EncryptedPemCase(String fileName, String password, boolean expectedPresent,
		String expectedAlgorithm) {
	}

	/**
	 * One call with a null argument
	 *
	 * @param description
	 *            what is passed as null
	 * @param call
	 *            the call
	 */
	record NullArgumentCase(String description, Executable call) {
	}

	@BeforeAll
	static void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
	}

	static Stream<EncryptedPemCase> encryptedPemCases()
	{
		return Stream.of(new EncryptedPemCase("rsa-pwp-pk-pw-is-123456.pem", "123456", true, "RSA"),
			new EncryptedPemCase("dsa-pwp-pk-pw-is-123456.pem", "123456", true, "DSA"),
			new EncryptedPemCase("test.key", "bosco", true, "RSA"),
			// a PKCS#8 encrypted key is not a traditional encrypted key pair
			new EncryptedPemCase("encrypted-key.pem", "password", false, null),
			// unencrypted keys are not touched at all
			new EncryptedPemCase("non-encrypted-key.pem", "password", false, null),
			new EncryptedPemCase("private.pem", "irrelevant", false, null));
	}

	/**
	 * Test method for {@link PemObjectReader#readPemPrivateKey(File, String)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if reading the file fails
	 */
	@ParameterizedTest
	@MethodSource("encryptedPemCases")
	void readPemPrivateKeyWithPassword(final EncryptedPemCase testCase) throws Exception
	{
		Optional<PrivateKey> actual = PemObjectReader
			.readPemPrivateKey(new File(pemDir, testCase.fileName()), testCase.password());

		assertEquals(testCase.expectedPresent(), actual.isPresent(), testCase.toString());
		if (testCase.expectedPresent())
		{
			assertEquals(testCase.expectedAlgorithm(), actual.get().getAlgorithm());
		}
	}

	static Stream<NullArgumentCase> nullArgumentCases()
	{
		File file = new File(PathFinder.getSrcTestResourcesDir(), "pem/private.pem");
		return Stream.of(
			new NullArgumentCase("getPemObject(File)",
				() -> PemObjectReader.getPemObject((File)null)),
			new NullArgumentCase("getPemObject(String)",
				() -> PemObjectReader.getPemObject((String)null)),
			new NullArgumentCase("isPemObject", () -> PemObjectReader.isPemObject(null)),
			new NullArgumentCase("readPemKeyObject", () -> PemObjectReader.readPemKeyObject(null)),
			new NullArgumentCase("readPemPrivateKey(File, String)",
				() -> PemObjectReader.readPemPrivateKey(null, "password")),
			new NullArgumentCase("readPemPrivateKey(File)",
				() -> PemObjectReader.readPemPrivateKey(null)),
			new NullArgumentCase("readPrivateKey: file",
				() -> PemObjectReader.readPrivateKey(null, KeyPairGeneratorAlgorithm.RSA)),
			new NullArgumentCase("readPrivateKey: algorithm",
				() -> PemObjectReader.readPrivateKey(file, null)),
			new NullArgumentCase("toPemFormat(PemObject)",
				() -> PemObjectReader.toPemFormat((org.bouncycastle.util.io.pem.PemObject)null)),
			new NullArgumentCase("toPemFormat(File)",
				() -> PemObjectReader.toPemFormat((File)null)),
			new NullArgumentCase("toDer", () -> PemObjectReader.toDer(null)),
			new NullArgumentCase("getPemType(PemObject)",
				() -> PemObjectReader.getPemType((org.bouncycastle.util.io.pem.PemObject)null)),
			new NullArgumentCase("getPemType(File)", () -> PemObjectReader.getPemType((File)null)));
	}

	/**
	 * Test method for the non-null contract of the {@link PemObjectReader} methods
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("nullArgumentCases")
	void nonNullContract(final NullArgumentCase testCase)
	{
		assertThrows(NullPointerException.class, testCase.call(), testCase.description());
	}
}
