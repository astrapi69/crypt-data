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

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.meanbean.lang.Factory;
import org.meanbean.test.BeanTester;
import org.meanbean.test.BeanVerifier;

import io.github.astrapi69.collection.array.ArrayFactory;

/**
 * Test class for {@link AesRsaCryptModel}
 */
public class AesRsaCryptModelTest
{

	/**
	 * Test to ensure the {@link AesRsaCryptModel} can be created successfully
	 */
	@Test
	void testAesRsaCryptModelCreation()
	{
		byte[] encryptedKey = { 1, 2, 3 };
		byte[] symmetricKeyEncryptedObject = { 4, 5, 6 };

		AesRsaCryptModel model = new AesRsaCryptModel(encryptedKey, symmetricKeyEncryptedObject);

		assertNotNull(model);
		assertArrayEquals(encryptedKey, model.getEncryptedKey());
		assertArrayEquals(symmetricKeyEncryptedObject, model.getSymmetricKeyEncryptedObject());
	}

	/**
	 * Parameterized test for {@link AesRsaCryptModel} using CSV file
	 *
	 * @param encryptedKeyStr
	 *            the encrypted key as a string
	 * @param symmetricKeyEncryptedObjectStr
	 *            the symmetric key encrypted object as a string
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/aesrsa_crypt_model_test_data.csv", numLinesToSkip = 1)
	void testAesRsaCryptModelParameterized(String encryptedKeyStr,
		String symmetricKeyEncryptedObjectStr)
	{
		byte[] encryptedKey = encryptedKeyStr.getBytes();
		byte[] symmetricKeyEncryptedObject = symmetricKeyEncryptedObjectStr.getBytes();

		AesRsaCryptModel model = new AesRsaCryptModel(encryptedKey, symmetricKeyEncryptedObject);

		assertNotNull(model);
		assertArrayEquals(encryptedKey, model.getEncryptedKey());
		assertArrayEquals(symmetricKeyEncryptedObject, model.getSymmetricKeyEncryptedObject());
	}

	/**
	 * Test method for {@link AesRsaCryptModel} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanVerifier.forClass(AesRsaCryptModel.class).editSettings()
			.registerFactory(byte[].class, new Factory<byte[]>()
			{
				@Override
				public byte[] create()
				{
					return ArrayFactory.newByteArray(1, 2, 3);
				}
			}).registerFactory(AesRsaCryptModel.class, new Factory<AesRsaCryptModel>()
			{
				@Override
				public AesRsaCryptModel create()
				{
					return AesRsaCryptModel.builder()
						.encryptedKey(ArrayFactory.newByteArray(1, 2, 3))
						.symmetricKeyEncryptedObject(ArrayFactory.newByteArray(1, 2, 3)).build();
				}
			}).edited().verify();
	}
}
