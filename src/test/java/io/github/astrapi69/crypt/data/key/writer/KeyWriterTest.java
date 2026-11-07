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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.meanbean.test.BeanTester;

/**
 * The unit test class for the class {@link KeyWriter}
 */
public class KeyWriterTest
{

	/** On Linux every write to this device fails with "No space left on device" */
	private static final Path DEV_FULL = Path.of("/dev/full");

	private static KeyPair keyPair;

	@BeforeAll
	static void setUpKeyPair() throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(256);
		keyPair = generator.generateKeyPair();
	}

	/**
	 * Test method for {@link KeyWriter#writeInPemFormat(java.security.Key, File)}: the file holds
	 * the key in PEM, with line feeds as line ends
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void writeInPemFormat_writesTheKeyInPemWithLineFeeds(@TempDir Path temporaryDirectory)
		throws Exception
	{
		File pemFile = temporaryDirectory.resolve("public.pem").toFile();

		KeyWriter.writeInPemFormat(keyPair.getPublic(), pemFile);

		String pem = Files.readString(pemFile.toPath(), StandardCharsets.US_ASCII);
		assertTrue(pem.startsWith("-----BEGIN PUBLIC KEY-----\n"), pem);
		assertTrue(pem.endsWith("-----END PUBLIC KEY-----\n"), pem);
		assertEquals(-1, pem.indexOf('\r'), pem);
	}

	/**
	 * Test method for {@link KeyWriter#writeInPemFormat(java.security.Key, File)} with a file that
	 * is a link to /dev/full, where the file opens and every write fails: today the method returns
	 * normally, as if the key had been written (#125)
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	@EnabledOnOs(OS.LINUX)
	public void writeInPemFormat_whenTheWriteFails_returnsNormally(@TempDir Path temporaryDirectory)
		throws Exception
	{
		File fullDisk = Files.createSymbolicLink(temporaryDirectory.resolve("full.pem"), DEV_FULL)
			.toFile();

		assertDoesNotThrow(() -> KeyWriter.writeInPemFormat(keyPair.getPublic(), fullDisk));
	}

	/**
	 * Test method for {@link KeyWriter} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyWriter.class);
	}

}
