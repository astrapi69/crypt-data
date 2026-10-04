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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.security.PrivateKey;
import java.security.Security;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.model.KeyInfo;
import io.github.astrapi69.file.search.PathFinder;

/**
 * Parameterized tests for {@link PrivateKeyReader#readPrivateKey(KeyInfo)} and for the password
 * protection and validity checks of {@link PrivateKeyReader}
 */
class PrivateKeyReaderKeyInfoParameterizedTest
{

	private static PrivateKey privateKey;

	/**
	 * One {@link KeyInfo} key type
	 *
	 * @param keyType
	 *            the key type display value
	 * @param expectedReadable
	 *            whether the reader accepts the info as private key
	 */
	record KeyInfoCase(String keyType, boolean expectedReadable) {
	}

	/**
	 * One private key file
	 *
	 * @param directory
	 *            the test resource sub directory
	 * @param fileName
	 *            the file name
	 * @param expectedPasswordProtected
	 *            whether the key in the file is password protected
	 * @param expectedKeyFormat
	 *            the key file format the reader must resolve
	 */
	record PrivateKeyFileCase(String directory, String fileName, boolean expectedPasswordProtected,
		KeyFileFormat expectedKeyFormat) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKey = PrivateKeyReader.readPrivateKey(new File(derDir, "private.der"));
	}

	static Stream<KeyInfoCase> keyInfoCases()
	{
		return Stream.of(new KeyInfoCase(KeyType.PRIVATE_KEY.getDisplayValue(), true),
			// the key type lookup ignores the case
			new KeyInfoCase("PRIVATE KEY", true),
			new KeyInfoCase(KeyType.PUBLIC_KEY.getDisplayValue(), false),
			new KeyInfoCase(KeyType.CERTIFICATE.getDisplayValue(), false),
			new KeyInfoCase(KeyType.PRIVATE_KEY_PASSWORD_PROTECTED.getDisplayValue(), false),
			new KeyInfoCase("no such key type", false));
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(KeyInfo)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if reading the key fails
	 */
	@ParameterizedTest
	@MethodSource("keyInfoCases")
	void readPrivateKeyFromKeyInfo(final KeyInfoCase testCase) throws Exception
	{
		KeyInfo keyInfo = KeyInfo.builder().keyType(testCase.keyType())
			.encoded(privateKey.getEncoded()).algorithm(privateKey.getAlgorithm()).build();

		if (testCase.expectedReadable())
		{
			assertEquals(privateKey, PrivateKeyReader.readPrivateKey(keyInfo));
		}
		else
		{
			RuntimeException actual = assertThrows(RuntimeException.class,
				() -> PrivateKeyReader.readPrivateKey(keyInfo));
			assertTrue(actual.getMessage().contains("is not a private key"), actual.getMessage());
		}
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(KeyInfo)} with null
	 */
	@Test
	void readPrivateKeyFromNullKeyInfo()
	{
		assertThrows(NullPointerException.class,
			() -> PrivateKeyReader.readPrivateKey((KeyInfo)null));
	}

	static Stream<PrivateKeyFileCase> privateKeyFileCases()
	{
		return Stream.of(
			// traditional OpenSSL encrypted key pairs
			new PrivateKeyFileCase("pem", "rsa-pwp-pk-pw-is-123456.pem", true,
				KeyFileFormat.UNKNOWN),
			new PrivateKeyFileCase("pem", "test.key", true, KeyFileFormat.UNKNOWN),
			// PKCS#8 encrypted key
			new PrivateKeyFileCase("pem", "encrypted-key.pem", true, KeyFileFormat.UNKNOWN),
			new PrivateKeyFileCase("der", "pwp-private-key-pw-is-secret.der", true,
				KeyFileFormat.UNKNOWN),
			// unprotected keys
			new PrivateKeyFileCase("pem", "private.pem", false, KeyFileFormat.PEM),
			new PrivateKeyFileCase("pem", "private2.pem", false, KeyFileFormat.PEM),
			new PrivateKeyFileCase("der", "private.der", false, KeyFileFormat.DER));
	}

	/**
	 * Test method for {@link PrivateKeyReader#isPrivateKeyPasswordProtected(File)},
	 * {@link PrivateKeyReader#validatePrivateKey(File)} and
	 * {@link PrivateKeyReader#getKeyFormat(File)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if reading the file fails
	 */
	@ParameterizedTest
	@MethodSource("privateKeyFileCases")
	void passwordProtectionAndValidity(final PrivateKeyFileCase testCase) throws Exception
	{
		File file = new File(new File(PathFinder.getSrcTestResourcesDir(), testCase.directory()),
			testCase.fileName());

		assertEquals(testCase.expectedPasswordProtected(),
			PrivateKeyReader.isPrivateKeyPasswordProtected(file), testCase.toString());
		// a password protected key cannot be read without its password, so it is not valid
		assertEquals(!testCase.expectedPasswordProtected(),
			PrivateKeyReader.validatePrivateKey(file), testCase.toString());
		assertEquals(testCase.expectedKeyFormat(), PrivateKeyReader.getKeyFormat(file),
			testCase.toString());
	}
}
