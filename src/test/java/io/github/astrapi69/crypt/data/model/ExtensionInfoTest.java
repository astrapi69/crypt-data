package io.github.astrapi69.crypt.data.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.reader.CertificateReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 * Test class for {@link ExtensionInfo}
 */
public class ExtensionInfoTest
{

	private ExtensionInfo extensionInfo;

	X509Certificate actual;
	X509Certificate caCert;
	String type;
	byte[] certificateData;
	File pemDir;
	File certificatePemFile;
	String base64EncodedCertificate;
	KeyPair keyPair;
	X500Name issuer;
	BigInteger serial;
	Date notBefore;
	Date notAfter;
	X500Name subject;
	String signatureAlgorithm;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp() throws IOException, CertificateException, NoSuchAlgorithmException,
		NoSuchProviderException, OperatorCreationException
	{
		extensionInfo = ExtensionInfo.builder().extensionId("1.2.3.4.5.6.7").critical(true)
			.value("testValue").build();
		Security.addProvider(new BouncyCastleProvider());

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		certificatePemFile = new File(pemDir, "certificate.pem");
		base64EncodedCertificate = CertificateReader.readPemFileAsBase64(certificatePemFile);
		certificateData = new Base64().decode(base64EncodedCertificate);
		type = "X.509";
		caCert = CertFactory.newX509Certificate(type, certificateData);


		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 2048);
		issuer = new X500Name("CN=Issuer of this certificate");
		serial = BigInteger.ONE;
		notBefore = Date.from(
			LocalDate.of(2017, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		notAfter = Date.from(
			LocalDate.of(2027, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		subject = new X500Name("CN=Subject of this certificate");
		signatureAlgorithm = "SHA1withRSA";
		actual = CertFactory.newEndEntityX509CertificateV3(keyPair, issuer, serial, notBefore,
			notAfter, subject, signatureAlgorithm, caCert);
		Set<String> nonCriticalExtensionOIDs = actual.getNonCriticalExtensionOIDs();
		Set<String> criticalExtensionOIDs = actual.getCriticalExtensionOIDs();
	}

	/**
	 * Test method for {@link ExtensionInfo#toExtension(ExtensionInfo)}
	 */
	@Test
	void testToExtension()
	{
		Extension extension = ExtensionInfo.toExtension(extensionInfo);
		assertNotNull(extension);
		assertEquals(extensionInfo.getExtensionId(), extension.getExtnId().getId());
		assertEquals(extensionInfo.isCritical(), extension.isCritical());
		assertEquals(extensionInfo.getValue(), new String(extension.getExtnValue().getOctets()));
	}

	/**
	 * Test method for {@link ExtensionInfo#fromExtension(Extension)}
	 */
	@Test
	void testFromExtension()
	{
		Extension extension = ExtensionInfo.toExtension(extensionInfo);
		ExtensionInfo result = ExtensionInfo.fromExtension(extension);
		assertNotNull(result);
		assertEquals(extensionInfo, result);
	}

	/**
	 * Test method for {@link ExtensionInfo#extractExtensionInfos(X509Certificate)}
	 */
	@Test
	void testExtractExtensionInfos()
	{
		X509Certificate mockCertificate = Mockito.mock(X509Certificate.class);

		Set<String> criticalOIDs = Set.of("1.2.3.4.5.6.8");
		Set<String> nonCriticalOIDs = Set.of("1.2.3.4.5.6.9");

		byte[] criticalValue = "criticalValue".getBytes();
		byte[] nonCriticalValue = "nonCriticalValue".getBytes();

		Mockito.when(mockCertificate.getCriticalExtensionOIDs()).thenReturn(criticalOIDs);
		Mockito.when(mockCertificate.getNonCriticalExtensionOIDs()).thenReturn(nonCriticalOIDs);
		Mockito.when(mockCertificate.getExtensionValue("1.2.3.4.5.6.8")).thenReturn(criticalValue);
		Mockito.when(mockCertificate.getExtensionValue("1.2.3.4.5.6.9"))
			.thenReturn(nonCriticalValue);

		List<ExtensionInfo> extensionInfos = ExtensionInfo.extractExtensionInfos(mockCertificate);
		assertNotNull(extensionInfos);
		assertEquals(2, extensionInfos.size());

		ExtensionInfo criticalExtensionInfo = extensionInfos.get(0);
		assertEquals("1.2.3.4.5.6.8", criticalExtensionInfo.getExtensionId());
		assertEquals(true, criticalExtensionInfo.isCritical());
		assertEquals("criticalValue", criticalExtensionInfo.getValue());

		ExtensionInfo nonCriticalExtensionInfo = extensionInfos.get(1);
		assertEquals("1.2.3.4.5.6.9", nonCriticalExtensionInfo.getExtensionId());
		assertEquals(false, nonCriticalExtensionInfo.isCritical());
		assertEquals("nonCriticalValue", nonCriticalExtensionInfo.getValue());
	}

	/**
	 * Test method for {@link ExtensionInfo#extractToExtensionInfoArray(X509Certificate)}
	 */
	@Test
	void testExtractToExtensionInfoArray()
	{
		X509Certificate certificate = getTestCertificate();
		ExtensionInfo[] extensionInfos = ExtensionInfo.extractToExtensionInfoArray(certificate);
		assertNotNull(extensionInfos);
		// Add assertions based on expected extensions in the test certificate
	}

	/**
	 * Utility method to get a test certificate
	 *
	 * @return a test certificate
	 */
	private X509Certificate getTestCertificate()
	{
		return actual;
	}
}
