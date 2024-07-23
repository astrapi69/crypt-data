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
