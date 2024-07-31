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
package io.github.astrapi69.crypt.data.factory;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * The unit test class for the class {@link CipherFactory}
 */
public class CipherFactoryParameterizedTest
{

	/**
	 * Parameterized test method for {@link CipherFactory#newCipher(CryptModel)}
	 *
	 * @param key
	 *            the key
	 * @param algorithm
	 *            the algorithm
	 * @param salt
	 *            the salt
	 * @param iterationCount
	 *            the iteration count
	 * @param operationMode
	 *            the operation mode
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             if generation of the SecretKey object fails
	 * @throws NoSuchPaddingException
	 *             if instantiation of the cipher object fails
	 * @throws InvalidKeyException
	 *             if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             if initialization of the cipher object fails
	 * @throws UnsupportedEncodingException
	 *             if the named charset is not supported
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/cipher_parameters.csv", numLinesToSkip = 1)
	public void testNewCipherParameterized(String key, String algorithm, String salt,
		int iterationCount, int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		Cipher actual;
		CryptModel<Cipher, String, String> encryptorModel;

		encryptorModel = CryptModel.<Cipher, String, String> builder().key(key)
			.algorithm(SunJCEAlgorithm.valueOf(algorithm)).salt(salt.getBytes())
			.iterationCount(iterationCount).operationMode(operationMode).build();

		actual = CipherFactory.newCipher(encryptorModel);
		assertNotNull(actual);
	}
}
