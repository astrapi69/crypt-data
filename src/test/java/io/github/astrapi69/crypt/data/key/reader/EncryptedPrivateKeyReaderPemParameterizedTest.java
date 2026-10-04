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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.file.search.PathFinder;

/**
 * Parameterized tests for {@link EncryptedPrivateKeyReader} with password protected pem files in
 * the traditional OpenSSL format and in the PKCS#8 format
 */
class EncryptedPrivateKeyReaderPemParameterizedTest
{

	private static File pemDir;

	/**
	 * One password protected pem file
	 *
	 * @param fileName
	 *            the name of the file in the pem test resource directory
	 * @param password
	 *            the password
	 * @param expectedAlgorithm
	 *            the algorithm of the private key
	 * @param expectedPublicKey
	 *            whether the pem file also yields the public key (traditional OpenSSL key pairs do,
	 *            PKCS#8 files do not)
	 */
	record EncryptedPemCase(String fileName, String password, String expectedAlgorithm,
		boolean expectedPublicKey) {
	}

	/**
	 * One password protected pem file read with a wrong password
	 *
	 * @param fileName
	 *            the name of the file in the pem test resource directory
	 * @param expectedException
	 *            the exception type the wrong password causes
	 */
	record WrongPasswordCase(String fileName, Class<? extends Exception> expectedException) {
	}

	@BeforeAll
	static void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
	}

	static Stream<EncryptedPemCase> encryptedPemCases()
	{
		return Stream.of(new EncryptedPemCase("encrypted-key.pem", "password", "RSA", false),
			new EncryptedPemCase("rsa-pwp-pk-pw-is-123456.pem", "123456", "RSA", true),
			new EncryptedPemCase("dsa-pwp-pk-pw-is-123456.pem", "123456", "DSA", true),
			new EncryptedPemCase("test.key", "bosco", "RSA", true));
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#getKeyPair(File, String)},
	 * {@link EncryptedPrivateKeyReader#readPasswordProtectedPrivateKey(File, String, String)} and
	 * {@link EncryptedPrivateKeyReader#getPrivateKey(File, String)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if reading the file fails
	 */
	@ParameterizedTest
	@MethodSource("encryptedPemCases")
	void readsPasswordProtectedPemFile(final EncryptedPemCase testCase) throws Exception
	{
		File encryptedPrivateKeyFile = new File(pemDir, testCase.fileName());

		KeyPair keyPair = EncryptedPrivateKeyReader.getKeyPair(encryptedPrivateKeyFile,
			testCase.password());

		assertNotNull(keyPair.getPrivate());
		assertEquals(testCase.expectedAlgorithm(), keyPair.getPrivate().getAlgorithm());
		assertEquals(testCase.expectedPublicKey(), keyPair.getPublic() != null);

		// the other entry points yield the very same private key
		PrivateKey viaAlgorithm = EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(
			encryptedPrivateKeyFile, testCase.password(), testCase.expectedAlgorithm());
		assertArrayEquals(keyPair.getPrivate().getEncoded(), viaAlgorithm.getEncoded());
		PrivateKey viaLookup = EncryptedPrivateKeyReader
			.readPasswordProtectedPrivateKey(encryptedPrivateKeyFile, testCase.password());
		assertArrayEquals(keyPair.getPrivate().getEncoded(), viaLookup.getEncoded());
		assertTrue(EncryptedPrivateKeyReader
			.getPrivateKey(encryptedPrivateKeyFile, testCase.password()).isPresent());
	}

	static Stream<WrongPasswordCase> wrongPasswordCases()
	{
		return Stream.of(new WrongPasswordCase("rsa-pwp-pk-pw-is-123456.pem", PEMException.class),
			new WrongPasswordCase("dsa-pwp-pk-pw-is-123456.pem", PEMException.class),
			new WrongPasswordCase("encrypted-key.pem", PKCSException.class));
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#getKeyPair(File, String)} with a wrong
	 * password
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("wrongPasswordCases")
	void rejectsWrongPassword(final WrongPasswordCase testCase)
	{
		File encryptedPrivateKeyFile = new File(pemDir, testCase.fileName());

		assertThrows(testCase.expectedException(),
			() -> EncryptedPrivateKeyReader.getKeyPair(encryptedPrivateKeyFile, "wrong password"));
	}
}
