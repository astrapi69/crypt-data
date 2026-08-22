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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.function.Function;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.model.KeyModel;

/**
 * Parameterized tests for the key type guards and the round trips of {@link KeyModelExtensions}
 */
class KeyModelExtensionsParameterizedTest
{

	private static KeyPair keyPair;

	/**
	 * One conversion of a {@link KeyModel} with the wrong key type
	 *
	 * @param description
	 *            what is converted
	 * @param keyType
	 *            the (wrong) key type of the model
	 * @param conversion
	 *            the conversion under test
	 * @param expectedMessagePart
	 *            the text the exception message must contain
	 */
	record WrongKeyTypeCase(String description, KeyType keyType,
		Function<KeyModel, Object> conversion, String expectedMessagePart) {
	}

	/**
	 * One conversion
	 *
	 * @param description
	 *            the conversion name
	 * @param conversion
	 *            the conversion under test
	 */
	record ConversionCase(String description, Function<KeyModel, Object> conversion) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 1024);
	}

	static Stream<WrongKeyTypeCase> wrongKeyTypeCases()
	{
		return Stream.of(
			new WrongKeyTypeCase("public key model to private key", KeyType.PUBLIC_KEY,
				KeyModelExtensions::toPrivateKey, "is not a private key"),
			new WrongKeyTypeCase("certificate model to private key", KeyType.CERTIFICATE,
				KeyModelExtensions::toPrivateKey, "is not a private key"),
			new WrongKeyTypeCase("private key model to public key", KeyType.PRIVATE_KEY,
				KeyModelExtensions::toPublicKey, "is not a public key"),
			new WrongKeyTypeCase("certificate model to public key", KeyType.CERTIFICATE,
				KeyModelExtensions::toPublicKey, "is not a public key"),
			new WrongKeyTypeCase("private key model to certificate", KeyType.PRIVATE_KEY,
				KeyModelExtensions::toX509Certificate, "is not a X509Certificate"),
			new WrongKeyTypeCase("public key model to certificate", KeyType.PUBLIC_KEY,
				KeyModelExtensions::toX509Certificate, "is not a X509Certificate"),
			new WrongKeyTypeCase("unknown model to private key", KeyType.UNKNOWN,
				KeyModelExtensions::toPrivateKey, "is not a private key"));
	}

	/**
	 * Test method for the key type guards of {@link KeyModelExtensions#toPrivateKey(KeyModel)},
	 * {@link KeyModelExtensions#toPublicKey(KeyModel)} and
	 * {@link KeyModelExtensions#toX509Certificate(KeyModel)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("wrongKeyTypeCases")
	void rejectsWrongKeyType(final WrongKeyTypeCase testCase)
	{
		KeyModel keyModel = KeyModel.builder().keyType(testCase.keyType())
			.encoded(keyPair.getPrivate().getEncoded()).algorithm("RSA").build();

		RuntimeException actual = assertThrows(RuntimeException.class,
			() -> testCase.conversion().apply(keyModel), testCase.description());

		assertTrue(actual.getMessage().contains(testCase.expectedMessagePart()),
			actual.getMessage());
		assertTrue(actual.getMessage().contains(keyModel.toString()), actual.getMessage());
	}

	static Stream<ConversionCase> conversionCases()
	{
		return Stream.of(new ConversionCase("toPrivateKey", KeyModelExtensions::toPrivateKey),
			new ConversionCase("toPublicKey", KeyModelExtensions::toPublicKey),
			new ConversionCase("toX509Certificate", KeyModelExtensions::toX509Certificate));
	}

	/**
	 * Test method for the non-null contract of the conversions
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("conversionCases")
	void rejectsNull(final ConversionCase testCase)
	{
		assertThrows(NullPointerException.class, () -> testCase.conversion().apply(null),
			testCase.description());
	}

	/**
	 * Test method for the round trip
	 * {@link KeyModelExtensions#toKeyModel(java.security.PrivateKey)} to
	 * {@link KeyModelExtensions#toPrivateKey(KeyModel)} and the public key counterpart
	 */
	@Test
	void keyModelRoundTrip()
	{
		KeyModel privateKeyModel = KeyModelExtensions.toKeyModel(keyPair.getPrivate());
		KeyModel publicKeyModel = KeyModelExtensions.toKeyModel(keyPair.getPublic());

		assertEquals(KeyType.PRIVATE_KEY, privateKeyModel.getKeyType());
		assertEquals(KeyType.PUBLIC_KEY, publicKeyModel.getKeyType());
		assertEquals(keyPair.getPrivate(), KeyModelExtensions.toPrivateKey(privateKeyModel));
		assertEquals(keyPair.getPublic(), KeyModelExtensions.toPublicKey(publicKeyModel));
	}
}
