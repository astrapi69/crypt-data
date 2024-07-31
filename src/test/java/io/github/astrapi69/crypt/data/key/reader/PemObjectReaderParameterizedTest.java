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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;

import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;


/**
 * The unit test class for the class {@link PemObjectReader}
 */
public class PemObjectReaderParameterizedTest
{

	/**
	 * Parameterized test for {@link PemObjectReader#getPemObject(File)} using a CSV file
	 *
	 * @param filePath
	 *            the path to the PEM file
	 * @param expectedType
	 *            the expected PEM type
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/pem_files.csv", numLinesToSkip = 1)
	public void testGetPemObjectParameterized(String filePath, String expectedType)
		throws IOException
	{
		File pemFile = new File(filePath);
		PemObject pemObject = PemObjectReader.getPemObject(pemFile);
		assertNotNull(pemObject);
		assertEquals(expectedType, pemObject.getType());
	}
}
