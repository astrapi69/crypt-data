package io.github.astrapi69.crypt.data.factory;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm;

/**
 * The unit test class for the class {@link SecretKeyFactoryExtensions}
 */
public class SecretKeyFactoryExtensionsTest
{

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKey(char[], String)}
	 */
	@Test
	public void testNewSecretKey() throws Exception
	{
		String algorithm;
		SecretKey secretKey;

		algorithm = SunJCEAlgorithm.PBEWithMD5AndDES.getAlgorithm();
		secretKey = SecretKeyFactoryExtensions.newSecretKey("secret".toCharArray(), algorithm);
		assertNotNull(secretKey);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKeyFactory(String)}
	 */
	@Test
	public void testNewSecretKeyFactory() throws Exception
	{
		String algorithm;
		SecretKeyFactory secretKeyFactory;

		algorithm = CompoundAlgorithm.PBE_WITH_MD5_AND_DES.getAlgorithm();
		secretKeyFactory = SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm);
		assertNotNull(secretKeyFactory);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKey(String, int)}
	 */
	@Test
	public void testNewSecretKeyWithKeyLength() throws Exception
	{
		String algorithm = "AES";
		int keyLength = 256;
		SecretKey secretKey = SecretKeyFactoryExtensions.newSecretKey(algorithm, keyLength);
		assertNotNull(secretKey);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKey(byte[], String)}
	 */
	@Test
	public void testNewSecretKeyWithByteArray() throws Exception
	{
		byte[] sharedSecret = "sharedSecret".getBytes();
		String algorithm = "AES";
		SecretKey secretKey = SecretKeyFactoryExtensions.newSecretKey(sharedSecret, algorithm);
		assertNotNull(secretKey);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(SecretKeyFactoryExtensions.class);
	}
}
