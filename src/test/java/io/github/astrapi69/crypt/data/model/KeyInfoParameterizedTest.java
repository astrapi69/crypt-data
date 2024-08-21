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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.github.astrapi69.crypt.data.key.KeyExtensions;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;

/**
 * The unit test class for the class {@link KeyInfo}
 */
public class KeyInfoParameterizedTest
{

	/**
	 * Parameterized test method for {@link KeyInfo} using CSV source
	 *
	 * @param keyType
	 *            the type of the key
	 * @param encoded
	 *            the encoded key
	 * @param algorithm
	 *            the algorithm of the key
	 */
	@ParameterizedTest(name = "{index} => keyType={0}, encoded.length={1}, algorithm={2}")
	@CsvFileSource(resources = "/keyinfo-test-data.csv", numLinesToSkip = 1)
	@DisplayName("Parameterized test for KeyInfo")
	public void testKeyInfoWithCsv(String keyType, String encoded, String algorithm)
		throws IOException
	{
		byte[] encodedBytes = KeyExtensions.decodeBase64(encoded); // For demonstration purposes,
																	// decode this appropriately
		KeyInfo keyInfo = KeyInfo.builder().encoded(encodedBytes).keyType(keyType)
			.algorithm(algorithm).build();

		assertNotNull(keyInfo);
		if (keyInfo.getKeyType().equals("Certificate"))
		{
			X509Certificate x509Certificate = KeyInfoExtensions.toX509Certificate(keyInfo);
			assertNotNull(x509Certificate);
		}
		if (keyInfo.getKeyType().equals("Public key"))
		{
			PublicKey publicKey = KeyInfoExtensions.toPublicKey(keyInfo);
			assertNotNull(publicKey);
		}
		if (keyInfo.getKeyType().equals("Private key"))
		{
			PrivateKey privateKey = KeyInfoExtensions.toPrivateKey(keyInfo);
			assertNotNull(privateKey);
		}
	}

}
