package io.github.astrapi69.crypt.data.key.reader;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

/**
 * The parameterized unit test class for the class {@link PrivateKeyReader}.
 */
public class PrivateKeyReaderParameterizedTest
{
	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}.
	 *
	 * @param filePath
	 *            the file path
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/privateKeyFiles.csv", numLinesToSkip = 1)
	public void testReadPrivateKey(String filePath) throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		File file = new File(filePath);
		PrivateKey actual = PrivateKeyReader.readPrivateKey(file);
		assertNotNull(actual);
	}
}
