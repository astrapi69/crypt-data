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
package io.github.astrapi69.crypto.factory;

import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import io.github.astrapi69.crypto.algorithm.Algorithm;
import io.github.astrapi69.crypto.algorithm.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypto.key.KeySize;
import io.github.astrapi69.crypto.key.PrivateKeyExtensions;
import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypto.key.reader.PublicKeyReader;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.random.SecureRandomBuilder;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The unit test class for the class {@link KeyPairFactory}
 */
public class KeyPairFactoryTest
{

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(Algorithm, KeySize)}
	 * 
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@Test
	public void testNewKeyPairAlgorithmKeySize()
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyPair actual;

		Security.addProvider(new BouncyCastleProvider());
		actual = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.DIFFIE_HELLMAN,
			KeySize.KEYSIZE_2048);
		assertNotNull(actual);

		actual = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.DSA, KeySize.KEYSIZE_2048);
		assertNotNull(actual);

		actual = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.EC, KeySize.KEYSIZE_2048);
		assertNotNull(actual);

		actual = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		assertNotNull(actual);

		actual = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSASSA_PSS,
			KeySize.KEYSIZE_2048);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(File, File)}
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@Test
	public void testNewKeyPairFileFile() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		File derDir;
		File publicKeyDerFile;
		File privateKeyDerFile;
		KeyPair actual;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publicKeyDerFile = new File(derDir, "public.der");
		privateKeyDerFile = new File(derDir, "private.der");

		actual = KeyPairFactory.newKeyPair(publicKeyDerFile, privateKeyDerFile);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPairGenerator(String, int, SecureRandom)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 */
	@Test
	public void testNewKeyPairGeneratorStringIntSecureRandom() throws NoSuchAlgorithmException
	{
		KeyPairGenerator actual;

		actual = KeyPairFactory.newKeyPairGenerator(KeyPairGeneratorAlgorithm.RSA.getAlgorithm(),
			KeySize.KEYSIZE_2048.getKeySize(), SecureRandomBuilder.getInstance().build());
		assertNotNull(actual);
		KeyPair keyPair = actual.generateKeyPair();
		String base64 = PrivateKeyExtensions.toBase64(keyPair.getPrivate());
		assertNotNull(base64);
		PrivateKey privateKey = RuntimeExceptionDecorator.decorate(() -> PrivateKeyReader
			.readPemPrivateKey(base64, KeyPairGeneratorAlgorithm.RSA.getAlgorithm()));
		assertNotNull(privateKey);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(PublicKey, PrivateKey)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testProtectPrivateKeyWithPassword() throws Exception
	{

		File publicKeyDerDir;
		File publicKeyDerFile;
		File privateKeyDerFile;
		PrivateKey privateKey;
		PublicKey publicKey;
		KeyPair keyPair;

		publicKeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publicKeyDerFile = new File(publicKeyDerDir, "public.der");
		privateKeyDerFile = new File(publicKeyDerDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privateKeyDerFile);

		publicKey = PublicKeyReader.readPublicKey(publicKeyDerFile);

		keyPair = KeyPairFactory.newKeyPair(publicKey, privateKey);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyPairFactory.class);
	}

}
