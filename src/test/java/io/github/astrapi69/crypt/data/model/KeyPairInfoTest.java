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


import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;
import org.meanbean.test.BeanVerifier;

import io.github.astrapi69.crypt.api.provider.SecurityProvider;

/**
 * Test class for {@link KeyPairInfo}.
 */
class KeyPairInfoTest
{

	private KeyPairInfo keyPairInfo;

	@BeforeEach
	void setUp()
	{
		keyPairInfo = KeyPairInfo.builder().algorithm("RSA").keySize(2048).build();
	}

	/**
	 * Test method for {@link KeyPairInfo#toKeyPair(KeyPairInfo)}
	 */
	@Test
	@DisplayName("Test toKeyPair method with valid data")
	void testToKeyPair()
	{
		assertDoesNotThrow(() -> {
			KeyPair keyPair = KeyPairInfo.toKeyPair(keyPairInfo);
			assertNotNull(keyPair);
		});
	}

	/**
	 * Test method for {@link KeyPairInfo#toKeyPairInfo(KeyPair)}
	 */
	@Test
	@DisplayName("Test toKeyPairInfo method with valid data")
	void testToKeyPairInfo() throws NoSuchAlgorithmException
	{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keyPair = keyGen.generateKeyPair();
		KeyPairInfo keyPairInfoFromKeyPair = KeyPairInfo.toKeyPairInfo(keyPair);

		assertEquals("RSA", keyPairInfoFromKeyPair.getAlgorithm());
		assertEquals(2048, keyPairInfoFromKeyPair.getKeySize());
	}

	/**
	 * Test method for {@link KeyPairInfo#isValid(KeyPairInfo)} with invalid data
	 */
	@Test
	@DisplayName("Test isValid method with invalid data")
	void testIsValidWithInvalidData()
	{
		KeyPairInfo invalidKeyPairInfo = KeyPairInfo.builder().algorithm("InvalidAlgorithm")
			.keySize(512).build();

		assertThrows(InvocationTargetException.class,
			() -> KeyPairInfo.isValid(invalidKeyPairInfo));
	}

	/**
	 * Test method for {@link KeyPairInfo} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanVerifier.forClass(KeyPairInfo.class).editSettings()
			.registerFactory(KeyPairInfo.class, () -> {
				return KeyPairInfo.builder().eCNamedCurveParameterSpecName("secp256r1")
					.algorithm("EC").provider(SecurityProvider.BC.name()).keySize(256).build();
			}).edited().verify();
	}

}
