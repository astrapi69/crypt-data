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
package io.github.astrapi69.crypt.data.hex;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

/**
 * The unit test class for the class {@link HexExtensions}
 */
public class HexExtensionsParameterizedTest
{

	/**
	 * Parameterized test method for {@link HexExtensions} using a CSV file
	 *
	 * @param secretMessage
	 *            the secret message
	 * @param hexString
	 *            the hexadecimal string representation of the message
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/hex_extensions_test_data.csv", numLinesToSkip = 1)
	public void testWithCsvSource(String secretMessage, String hexString) throws DecoderException
	{
		String actual;

		actual = HexExtensions.decodeHex(hexString);
		assertEquals(secretMessage, actual);

		actual = new String(HexExtensions.encodeHex(secretMessage));
		assertEquals(hexString.toLowerCase(), actual);
	}
}
