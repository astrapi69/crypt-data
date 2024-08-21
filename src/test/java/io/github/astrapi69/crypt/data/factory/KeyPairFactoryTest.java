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

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeySize;
import io.github.astrapi69.crypt.api.provider.SecurityProvider;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.crypt.data.model.KeyPairInfo;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link KeyPairFactory}
 */
public class KeyPairFactoryTest
{

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@BeforeEach
	protected void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
	}

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
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
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

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(ECNamedCurveParameterSpec, String, String)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testNewKeyPairWithECNamedCurveParameterSpec()
		throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException
	{
		// the name of the curve
		KeyPair keyPair;
		String eCurveNameAlgorithm;
		final String algorithm;
		final String provider;
		ECNamedCurveParameterSpec parameterSpec;

		algorithm = "ECDH";
		provider = SecurityProvider.BC.name();
		eCurveNameAlgorithm = "brainpoolp256r1";

		parameterSpec = ECNamedCurveTable.getParameterSpec(eCurveNameAlgorithm);

		keyPair = KeyPairFactory.newKeyPair(parameterSpec, algorithm, provider);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(ECNamedCurveParameterSpec, String, String)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testNewKeyPairWithECNamedCurveParameterSpecAsString()
		throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException
	{

		KeyPair keyPair;
		// the name of the curve
		String eCurveNameAlgorithm;
		final String algorithm;
		final String provider;


		eCurveNameAlgorithm = "brainpoolp256r1";
		algorithm = "ECDH";
		provider = SecurityProvider.BC.name();

		keyPair = KeyPairFactory.newKeyPair(eCurveNameAlgorithm, algorithm, provider);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(String)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@Test
	public void testNewKeyPairWithDefaultKeySize()
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyPair keyPair;

		keyPair = KeyPairFactory.newKeyPair("RSA");
		assertNotNull(keyPair);

		keyPair = KeyPairFactory.newKeyPair("DSA");
		assertNotNull(keyPair);

		keyPair = KeyPairFactory.newKeyPair("EC");
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(Algorithm)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@Test
	public void testNewKeyPairAlgorithm() throws NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyPair keyPair;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA);
		assertNotNull(keyPair);

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.DSA);
		assertNotNull(keyPair);

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.EC);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(PrivateKey)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 */
	@Test
	public void testNewKeyPairPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException,
		IOException, NoSuchProviderException
	{
		File derDir;
		File privateKeyDerFile;
		PrivateKey privateKey;
		KeyPair keyPair;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privateKeyDerFile);

		keyPair = KeyPairFactory.newKeyPair(privateKey);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(KeyPairInfo)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails
	 */
	@Test
	public void testNewKeyPairKeyPairInfo()
		throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		KeyPairInfo keyPairInfo;
		KeyPair keyPair;

		keyPairInfo = KeyPairInfo.builder().algorithm("ECDH")
			.eCNamedCurveParameterSpecName("brainpoolp256r1").provider(SecurityProvider.BC.name())
			.build();

		keyPair = KeyPairFactory.newKeyPair(keyPairInfo);
		assertNotNull(keyPair);

		keyPairInfo = KeyPairInfo.builder().algorithm("ECDH")
			.eCNamedCurveParameterSpecName("brainpoolp256r1").build();

		keyPair = KeyPairFactory.newKeyPair(keyPairInfo);
		assertNotNull(keyPair);

		keyPairInfo = KeyPairInfo.builder().algorithm("RSA").keySize(2048).build();

		keyPair = KeyPairFactory.newKeyPair(keyPairInfo);
		assertNotNull(keyPair);
	}
}
