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
package io.github.astrapi69.crypt.data.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;

import org.junit.jupiter.api.Test;

/**
 * Test class for {@link ExtensionInfoCSVReader}
 */
public class ExtensionInfoCSVReaderTest
{

	/**
	 * Test method for {@link ExtensionInfoCSVReader#readExtensionInfoFromCSV(String)}
	 */
	@Test
	void testReadExtensionInfoFromCSV() throws IOException
	{
		ExtensionInfo[] extensionInfos = ExtensionInfoCSVReader
			.readExtensionInfoFromCSV("src/test/resources/extension_info_data.csv");

		assertNotNull(extensionInfos);
		assertEquals(17, extensionInfos.length);

		ExtensionInfo firstExtension = extensionInfos[0];
		assertEquals("1.3.6.1.4.1.11129.2.4.2", firstExtension.getExtensionId());
		assertEquals(true, firstExtension.isCritical());
		assertEquals("testValue1", firstExtension.getValue());

		ExtensionInfo secondExtension = extensionInfos[1];
		assertEquals("1.2.840.113549.1.1.5", secondExtension.getExtensionId());
		assertEquals(false, secondExtension.isCritical());
		assertEquals("testValue2", secondExtension.getValue());
	}
}
