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
import java.security.PrivateKey;
import java.security.Security;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyFormat;
import io.github.astrapi69.crypt.api.key.PemType;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.crypt.data.key.reader.PemObjectReader;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 * Parameterized tests for
 * {@link PrivateKeyWriter#write(PrivateKey, java.io.OutputStream, KeyFileFormat, KeyFormat)}
 * covering every combination of file format and key format
 */
class PrivateKeyWriterFormatParameterizedTest
{

	private static PrivateKey privateKey;

	/**
	 * One combination of file format and key format
	 *
	 * @param fileFormat
	 *            the file format
	 * @param keyFormat
	 *            the key format, may be null
	 * @param expectedPem
	 *            whether the output is expected in pem format, otherwise der is expected
	 */
	record WriteCase(KeyFileFormat fileFormat, KeyFormat keyFormat, boolean expectedPem) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKey = PrivateKeyReader.readPrivateKey(new File(derDir, "private.der"));
	}

	static Stream<WriteCase> writeCases()
	{
		return Stream.of(new WriteCase(KeyFileFormat.PEM, KeyFormat.PKCS_8, true),
			new WriteCase(KeyFileFormat.PEM, null, true),
			new WriteCase(KeyFileFormat.PEM, KeyFormat.PKCS_1, true),
			// an unknown key format falls back to der although pem was requested
			new WriteCase(KeyFileFormat.PEM, KeyFormat.UNKNOWN, false),
			new WriteCase(KeyFileFormat.DER, null, false),
			new WriteCase(KeyFileFormat.DER, KeyFormat.PKCS_8, false),
			new WriteCase(KeyFileFormat.P7B, null, false),
			new WriteCase(KeyFileFormat.UNKNOWN, null, false));
	}

	/**
	 * Test method for
	 * {@link PrivateKeyWriter#write(PrivateKey, java.io.OutputStream, KeyFileFormat, KeyFormat)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if writing fails
	 */
	@ParameterizedTest
	@MethodSource("writeCases")
	void write(final WriteCase testCase) throws Exception
	{
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		PrivateKeyWriter.write(privateKey, outputStream, testCase.fileFormat(),
			testCase.keyFormat());
		byte[] written = outputStream.toByteArray();

		if (testCase.expectedPem())
		{
			String pem = new String(written, StandardCharsets.US_ASCII);
			assertTrue(pem.startsWith("-----BEGIN RSA PRIVATE KEY-----"), pem);
			PemObject pemObject = PemObjectReader.getPemObject(pem);
			assertEquals(PemType.RSA_PRIVATE_KEY.getName(), pemObject.getType());
			assertArrayEquals(PrivateKeyExtensions.toPKCS1Format(privateKey),
				pemObject.getContent());
		}
		else
		{
			assertArrayEquals(privateKey.getEncoded(), written);
		}
	}
}
