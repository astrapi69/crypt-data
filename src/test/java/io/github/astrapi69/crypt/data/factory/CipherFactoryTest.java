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
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.api.compound.CompoundAlgorithm;
import io.github.astrapi69.crypt.api.provider.SecurityProvider;
import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * The unit test class for the class {@link CipherFactory}
 */
public class CipherFactoryTest
{

	/**
	 * Test method for {@link CipherFactory#newCipher(CryptModel)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported
	 */
	@Test
	public void testNewCipherCryptModelOfCipherString()
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		Cipher actual;
		String privateKey;
		CryptModel<Cipher, String, String> encryptorModel;

		privateKey = "D1D15ED36B887AF1";
		encryptorModel = CryptModel.<Cipher, String, String> builder().key(privateKey)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(CompoundAlgorithm.SALT)
			.iterationCount(CompoundAlgorithm.ITERATIONCOUNT).operationMode(Cipher.ENCRYPT_MODE)
			.build();

		actual = CipherFactory.newCipher(encryptorModel);
		assertNotNull(actual);
	}

	/**
	 * Test method for
	 * {@link CipherFactory#newCipher(int, SecretKey, AlgorithmParameterSpec, String)}
	 */
	@Test
	public void testNewCipherIntSecretKeyAlgorithmParameterSpecString() throws Exception
	{
		String algorithm;
		KeySpec keySpec;
		SecretKeyFactory factory;
		SecretKey key;
		int operationMode;
		AlgorithmParameterSpec paramSpec;
		Cipher cipher;

		algorithm = CompoundAlgorithm.PBE_WITH_MD5_AND_DES.getAlgorithm();
		keySpec = KeySpecFactory.newPBEKeySpec(CompoundAlgorithm.PRIVATE_KEY,
			CompoundAlgorithm.SALT, CompoundAlgorithm.ITERATIONCOUNT);
		factory = SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm);
		key = factory.generateSecret(keySpec);

		operationMode = Cipher.ENCRYPT_MODE;
		paramSpec = AlgorithmParameterSpecFactory.newPBEParameterSpec(CompoundAlgorithm.SALT,
			CompoundAlgorithm.ITERATIONCOUNT);
		cipher = CipherFactory.newCipher(operationMode, key, paramSpec, algorithm);
		assertNotNull(cipher);
	}

	/**
	 * Test method for {@link CipherFactory#newCipher(String)}
	 */
	@Test
	public void testNewCipherString() throws Exception
	{
		String algorithm;
		Cipher cipher;

		algorithm = CompoundAlgorithm.PBE_WITH_MD5_AND_DES.getAlgorithm();
		cipher = CipherFactory.newCipher(algorithm);
		assertNotNull(cipher);
	}

	/**
	 * Test method for {@link CipherFactory#newCipher(String, String)}
	 */
	@Test
	public void testNewCipherStringString() throws Exception
	{
		String algorithm;
		Cipher cipher;

		Security.addProvider(new BouncyCastleProvider());
		algorithm = "AES/CBC/PKCS5Padding";
		cipher = CipherFactory.newCipher(algorithm, SecurityProvider.BC.name());
		assertNotNull(cipher);
	}

	/**
	 * Test method for {@link CipherFactory#newCipher(String, String, byte[], int, int)}
	 */
	@Test
	public void testNewCipherStringStringByteArrayIntInt() throws Exception
	{
		String algorithm;
		Cipher cipher;
		int operationMode;

		algorithm = CompoundAlgorithm.PBE_WITH_MD5_AND_DES.getAlgorithm();
		operationMode = Cipher.ENCRYPT_MODE;
		cipher = CipherFactory.newCipher(CompoundAlgorithm.PRIVATE_KEY, algorithm,
			CompoundAlgorithm.SALT, CompoundAlgorithm.ITERATIONCOUNT, operationMode);
		assertNotNull(cipher);
	}

	/**
	 * Test method for {@link CipherFactory} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(CipherFactory.class);
	}

}
