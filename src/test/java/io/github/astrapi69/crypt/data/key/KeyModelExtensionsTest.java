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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.model.KeyModel;

class KeyModelExtensionsTest
{

	@BeforeEach
	void setUp()
	{
		// Any setup code if needed
	}

	@ParameterizedTest
	@CsvFileSource(resources = "/private_key_data.csv", numLinesToSkip = 1)
	void testToPrivateKey(String keyType, String encoded, String algorithm)
	{
		byte[] decoded = Base64.getDecoder().decode(encoded);
		KeyModel keyModel = KeyModel.builder().keyType(KeyType.toKeyType(keyType)).encoded(decoded)
			.algorithm(algorithm).build();
		try
		{
			PrivateKey privateKey = KeyModelExtensions.toPrivateKey(keyModel);
			assertNotNull(privateKey);
		}
		catch (Exception e)
		{
			fail("Failed to convert to private key: " + e.getMessage());
		}
	}

	@ParameterizedTest
	@CsvFileSource(resources = "/public_key_data.csv", numLinesToSkip = 1)
	void testToPublicKey(String keyType, String encoded, String algorithm)
	{
		KeyModel keyModel = KeyModel.builder().keyType(KeyType.toKeyType(keyType))
			.encoded(Base64.getDecoder().decode(encoded)).algorithm(algorithm).build();

		PublicKey result = KeyModelExtensions.toPublicKey(keyModel);
		assertNotNull(result);
	}

	@ParameterizedTest
	@CsvFileSource(resources = "/certificate_data.csv", numLinesToSkip = 1)
	void testToX509Certificate(String keyType, String encoded, String algorithm)
	{
		KeyModel keyModel = KeyModel.builder().keyType(KeyType.toKeyType(keyType))
			.encoded(Base64.getDecoder().decode(encoded)).algorithm(algorithm).build();

		X509Certificate result = KeyModelExtensions.toX509Certificate(keyModel);
		assertNotNull(result);
	}

	@ParameterizedTest
	@CsvFileSource(resources = "/private_key_data.csv", numLinesToSkip = 1)
	void testToKeyInfoPrivateKey(String keyType, String encoded, String algorithm)
	{
		PrivateKey privateKey = mock(PrivateKey.class);
		when(privateKey.getEncoded()).thenReturn(Base64.getDecoder().decode(encoded));
		when(privateKey.getAlgorithm()).thenReturn(algorithm);

		KeyModel result = KeyModelExtensions.toKeyModel(privateKey);
		assertNotNull(result);
		assertEquals(KeyType.toKeyType(keyType), result.getKeyType());
		assertArrayEquals(Base64.getDecoder().decode(encoded), result.getEncoded());
		assertEquals(algorithm, result.getAlgorithm());
	}

	@ParameterizedTest
	@CsvFileSource(resources = "/public_key_data.csv", numLinesToSkip = 1)
	void testToKeyInfoPublicKey(String keyType, String encoded, String algorithm)
	{
		PublicKey publicKey = mock(PublicKey.class);
		when(publicKey.getEncoded()).thenReturn(Base64.getDecoder().decode(encoded));
		when(publicKey.getAlgorithm()).thenReturn(algorithm);

		KeyModel result = KeyModelExtensions.toKeyModel(publicKey);
		assertNotNull(result);
		assertEquals(KeyType.toKeyType(keyType), result.getKeyType());
		assertArrayEquals(Base64.getDecoder().decode(encoded), result.getEncoded());
		assertEquals(algorithm, result.getAlgorithm());
	}

	@ParameterizedTest
	@CsvFileSource(resources = "/certificate_data.csv", numLinesToSkip = 1)
	void testToKeyInfoCertificate(String keyType, String encoded, String algorithm)
		throws CertificateEncodingException
	{
		KeyModel keyModel = KeyModel.builder().keyType(KeyType.toKeyType(keyType))
			.encoded(Base64.getDecoder().decode(encoded)).algorithm(algorithm).build();

		X509Certificate certificate = KeyModelExtensions.toX509Certificate(keyModel);

		KeyModel result = KeyModelExtensions.toKeyModel(certificate);
		assertNotNull(result);
		assertEquals(KeyType.toKeyType(keyType), result.getKeyType());
		assertArrayEquals(Base64.getDecoder().decode(encoded), result.getEncoded());
	}
}
