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
