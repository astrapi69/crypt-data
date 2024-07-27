package io.github.astrapi69.crypt.data.factory;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;


/**
 * The parameterized test class for the class {@link KeyStoreFactory}
 */
public class KeyStoreFactoryParameterizedTest
{

	private char[] password;

	@TempDir
	Path tempDir;

	@BeforeEach
	public void setUp()
	{
		password = "password".toCharArray();
	}

	/**
	 * Test for {@link KeyStoreFactory#loadKeyStore(File, String, String)} using parameterized data
	 *
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore
	 * @param fileName
	 *            the name of the keystore file
	 * @throws KeyStoreException
	 *             if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             if there is an error with a certificate
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/keystore-parameters.csv", numLinesToSkip = 1)
	public void testLoadKeyStore(String type, String password, String fileName)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		File keystoreFile = new File(tempDir.toFile(), fileName);

		// Create the keystore file if it does not exist
		if (!keystoreFile.exists())
		{
			createKeystoreFile(keystoreFile, type, password.toCharArray());
		}

		// Load the keystore file
		KeyStore keystore = KeyStoreFactory.loadKeyStore(keystoreFile, type, password);
		assertNotNull(keystore);
	}

	private void createKeystoreFile(File keystoreFile, String type, char[] password)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		KeyStore keyStore = KeyStore.getInstance(type);
		keyStore.load(null, password); // Initialize the keystore
		try (FileOutputStream fos = new FileOutputStream(keystoreFile))
		{
			keyStore.store(fos, password); // Store the empty keystore
		}
		catch (IOException e)
		{
			System.err.println("Failed to create keystore file: " + e.getMessage());
			throw e;
		}
	}
}
