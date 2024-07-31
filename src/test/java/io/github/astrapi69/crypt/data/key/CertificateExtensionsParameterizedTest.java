package io.github.astrapi69.crypt.data.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;
import io.github.astrapi69.crypt.data.key.reader.CertificateReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The parameterized test class for the class {@link CertificateExtensions}
 */
public class CertificateExtensionsParameterizedTest
{

	/** The certificate for tests */
	private X509Certificate certificate;

	/**
	 * Sets up method will be invoked before every parameterized test method in this class
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@BeforeEach
	protected void setUp() throws Exception
	{
		if (certificate == null)
		{
			final File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
			final File certificatePemFile = new File(pemDir, "certificate.pem");
			certificate = CertificateReader.readPemCertificate(certificatePemFile);
		}
	}

	/**
	 * Parameterized test method for
	 * {@link CertificateExtensions#getFingerprint(X509Certificate, HashAlgorithm)}
	 *
	 * @param hashAlgorithm
	 *            the hash algorithm
	 * @param expected
	 *            the expected fingerprint
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/fingerprint_test_data.csv", numLinesToSkip = 1)
	public void testGetFingerprint(HashAlgorithm hashAlgorithm, String expected)
		throws CertificateEncodingException, NoSuchAlgorithmException
	{
		String actual = CertificateExtensions.getFingerprint(certificate, hashAlgorithm);
		assertEquals(expected, actual);
	}
}
