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
package io.github.astrapi69.crypto.factories;

import static org.testng.Assert.assertNotNull;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import io.github.astrapi69.search.PathFinder;
import io.github.astrapi69.crypto.algorithm.Algorithm;
import io.github.astrapi69.crypto.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypto.key.reader.PublicKeyReader;
import io.github.astrapi69.crypto.model.CryptModel;

/**
 * The unit test class for the class {@link CryptModelFactory}
 */
public class CryptModelFactoryTest
{

	/**
	 * Test method for {@link CryptModelFactory#newCryptModel(PublicKey)}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testNewCryptModelWithPublicKey() throws Exception
	{
		PublicKey publicKey;
		CryptModel<Cipher, PublicKey, byte[]> cryptModel;
		File publickeyDerDir;
		File publickeyDerFile;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);
		cryptModel = CryptModelFactory.newCryptModel(publicKey);
		assertNotNull(cryptModel);
	}

	/**
	 * Test method for {@link CryptModelFactory#newCryptModel(PrivateKey)}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testNewCryptModelWithPrivateKey() throws Exception
	{
		PrivateKey privateKey;
		CryptModel<Cipher, PrivateKey, byte[]> cryptModel;
		File derDir;
		File privatekeyDerFile;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		cryptModel = CryptModelFactory.newCryptModel(privateKey);
		assertNotNull(cryptModel);
	}

	/**
	 * Test method for {@link CryptModelFactory#newCryptModel(Algorithm, String)}
	 */
	@Test
	public void testNewCryptModelWithAlgorithmAndStringKey()
	{
		String key;
		Algorithm algorithm;
		CryptModel<Cipher, String, String> cryptModel;

		key = "D1D15ED36B887AF1";
		algorithm = SunJCEAlgorithm.PBEWithMD5AndDES;
		cryptModel = CryptModel.<Cipher, String, String> builder().key(key).algorithm(algorithm)
			.build();
		assertNotNull(cryptModel);
	}

	/**
	 * Test method for {@link CryptModelFactory} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(CryptModelFactory.class);
	}
}
