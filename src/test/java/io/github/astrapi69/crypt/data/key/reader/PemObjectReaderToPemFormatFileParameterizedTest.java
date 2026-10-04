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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.file.search.PathFinder;

/**
 * Parameterized test for {@link PemObjectReader#toPemFormat(File)}: pem files yield their pem text,
 * anything else yields an empty {@link Optional}
 */
class PemObjectReaderToPemFormatFileParameterizedTest
{

	/**
	 * One key file
	 *
	 * @param directory
	 *            the resource sub directory
	 * @param fileName
	 *            the file name
	 * @param expectedPresent
	 *            whether a pem representation is expected
	 */
	record PemFileCase(String directory, String fileName, boolean expectedPresent) {
	}

	static Stream<PemFileCase> pemFileCases()
	{
		return Stream.of(new PemFileCase("pem", "private.pem", true),
			new PemFileCase("pem", "public.pem", true),
			new PemFileCase("pem", "certificate.pem", true),
			new PemFileCase("der", "private.der", false));
	}

	/**
	 * Test method for {@link PemObjectReader#toPemFormat(File)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	@ParameterizedTest
	@MethodSource("pemFileCases")
	void toPemFormatOfFile(final PemFileCase testCase) throws IOException
	{
		File file = new File(new File(PathFinder.getSrcTestResourcesDir(), testCase.directory()),
			testCase.fileName());

		Optional<String> actual = PemObjectReader.toPemFormat(file);

		assertEquals(testCase.expectedPresent(), actual.isPresent(), testCase.toString());
		if (testCase.expectedPresent())
		{
			String pem = actual.get();
			assertTrue(pem.startsWith("-----BEGIN "), pem);
			assertTrue(pem.trim().endsWith("-----"), pem);
			assertEquals(PemObjectReader.toPemFormat(PemObjectReader.getPemObject(file)), pem);
			assertFalse(pem.isBlank());
		}
	}
}
