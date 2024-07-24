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
package io.github.astrapi69.crypt.data.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.github.astrapi69.crypt.data.hex.HexExtensions;

/**
 * Parameterized tests for the class {@link KeyExtensions}.
 */
@DisplayName("Parameterized tests for KeyExtensions")
class KeyExtensionsParameterizedTest
{

	/**
	 * Parameterized test for base64 encoding and decoding with CSV data.
	 *
	 * @param originalKeyHex
	 *            the original key in hexadecimal format
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/key_data.csv", numLinesToSkip = 1)
	@DisplayName("Parameterized test for base64 encoding and decoding with CSV data")
	void testBase64EncodingDecodingWithCsv(String originalKeyHex) throws DecoderException
	{
		byte[] originalKey = HexExtensions.decodeHex(originalKeyHex.toCharArray());
		String base64Encoded = KeyExtensions.toBase64(originalKey);
		byte[] decodedKey = KeyExtensions.decodeBase64(base64Encoded);
		assertArrayEquals(originalKey, decodedKey);
	}
}
