package io.github.astrapi69.crypt.data.factory;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import javax.crypto.SecretKey;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

/**
 * Parameterized test class for {@link SecretKeyFactoryExtensions}
 */
public class SecretKeyFactoryExtensionsParameterizedTest
{

	/**
	 * Parameterized test method for {@link SecretKeyFactoryExtensions#newSecretKey(char[], String)}
	 *
	 * @param password
	 *            the password
	 * @param algorithm
	 *            the algorithm
	 * @throws Exception
	 *             if an error occurs during the test
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/secretKeyTestData.csv", numLinesToSkip = 1)
	public void testNewSecretKeyParameterized(String password, String algorithm) throws Exception
	{
		SecretKey secretKey = SecretKeyFactoryExtensions.newSecretKey(password.toCharArray(),
			algorithm);
		assertNotNull(secretKey);
	}
}
