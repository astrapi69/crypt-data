package io.github.astrapi69.crypt.data.certificate;

import io.github.astrapi69.crypt.data.key.CertificateExtensions;
import io.github.astrapi69.crypt.data.key.reader.CertificateReader;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.time.convert.ZonedDateTimeExtensions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.security.cert.X509Certificate;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CertificateInfoTest
{

	/** The certificate for tests. */
	private X509Certificate certificate;

	/**
	 * Sets up method will be invoked before every unit test method in this class.
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
			assertNotNull(certificate);
		}
	}

	@Test
	public void loadCert()
	{
		CertificateInfo actual = CertificateExtensions.toCertificateInfo(certificate);
		assertNotNull(actual);
	}
}
