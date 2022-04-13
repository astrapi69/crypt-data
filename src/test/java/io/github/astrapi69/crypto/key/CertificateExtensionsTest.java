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
package io.github.astrapi69.crypto.key;

import static org.testng.Assert.assertNotNull;
import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.crypto.algorithm.HashAlgorithm;
import io.github.astrapi69.crypto.compound.CompoundAlgorithm;
import io.github.astrapi69.crypto.key.reader.CertificateReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link CertificateExtensions}
 */
public class CertificateExtensionsTest
{

	/** The certificate for tests. */
	private X509Certificate certificate;


	/**
	 * Sets up method will be invoked before every unit test method in this class.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@BeforeMethod
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

	/**
	 * Test method for {@link CertificateExtensions#toHex(X509Certificate)}
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	@Test
	public void testToHex() throws CertificateEncodingException
	{
		String expected;
		String actual;

		actual = CertificateExtensions.toHex(certificate);
		expected = "308202ac30820194a00302010202087d16e0c8bf2831fe300d06092a864886f70d01010b05003015311330110603550403130a54657374206973737565301e170d3136313233313233303030305a170d3236313233313233303030305a3017311530130603550403130c54657374207375626a65637430820122300d06092a864886f70d01010105000382010f003082010a0282010100de9ad9316a7690eeab7c434ee29ed728d2bd3868ac26cc78286d6019f49cb337507c8c56ffa29a0045a08544a17759f6b725fa2e8dd4a80e6df4eca1c949ed5e7010d8264f63936ad9ae4709b1f67bd408cc97623c13425d3b37c08a6b20626fd93d0ef6a90e1bb088aa16638ab9e168650002a312d21bd50e7f80029cefd0570989d68ee6a5f9e8bb28e653e93960910441eac10c9b5e116b0e96d36d8d2ed0a857a200e743e8c6b7d94c12cf121af287d05b96dd3b97b03351938b874bdc3f8db6f1d430b5b2314cbf78cd1e8e13acaa29bd195c2f60f7b87a7f880008794f835de6525081118bf155910c4835125fd9b01dbd134381316d0945b8250766610203010001300d06092a864886f70d01010b05000382010100db2379ea0494e5a4da28c96069f8f71eb3e0827914b1a52a6729578192f41d436f30007e9f14b759068f255e0f7fedd6c9d243fc6a14b261e3565eaf2bafe5e9533da99e89b8d2a9b4bfa86aef5e9376e38f98e7020092dc749560fcb501de94b3cfbf79dac84ceb8ec4c0bbb2cafc04e255947a7d53e93f9ddc94680420b5f0cd91e1da2266b394250ea2c08d738d6df2110be819fe49010cfc3723b1256112bc868b02513609552630c63eb0f7d733d4116b8b06770e8a97a9cef3787f7bacb371ad0297e94b4126f676f35fbd8987c7ba96f33e4818ad4fceb90188c68072de5bfe7f0449b7ef4dcfed5c36f53aa883b7a64fc5eba0dbf49093f7c94cbd88";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#toBase64(X509Certificate)}
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	@Test
	public void testToBase64() throws CertificateEncodingException
	{
		String expected;
		String actual;

		actual = CertificateExtensions.toBase64(certificate);
		expected = "MIICrDCCAZSgAwIBAgIIfRbgyL8oMf4wDQYJKoZIhvcNAQELBQAwFTETMBEGA1UEAxMKVGVzdCBpc3N1ZTAeFw0xNjEyMzEyMzAwMDBaFw0yNjEyMzEyMzAwMDBaMBcxFTATBgNVBAMTDFRlc3Qgc3ViamVjdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN6a2TFqdpDuq3xDTuKe1yjSvThorCbMeChtYBn0nLM3UHyMVv+imgBFoIVEoXdZ9rcl+i6N1KgObfTsoclJ7V5wENgmT2OTatmuRwmx9nvUCMyXYjwTQl07N8CKayBib9k9DvapDhuwiKoWY4q54WhlAAKjEtIb1Q5/gAKc79BXCYnWjual+ei7KOZT6TlgkQRB6sEMm14Raw6W022NLtCoV6IA50PoxrfZTBLPEhryh9Bblt07l7AzUZOLh0vcP4228dQwtbIxTL94zR6OE6yqKb0ZXC9g97h6f4gACHlPg13mUlCBEYvxVZEMSDUSX9mwHb0TQ4ExbQlFuCUHZmECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA2yN56gSU5aTaKMlgafj3HrPggnkUsaUqZylXgZL0HUNvMAB+nxS3WQaPJV4Pf+3WydJD/GoUsmHjVl6vK6/l6VM9qZ6JuNKptL+oau9ek3bjj5jnAgCS3HSVYPy1Ad6Us8+/edrITOuOxMC7ssr8BOJVlHp9U+k/ndyUaAQgtfDNkeHaImazlCUOosCNc41t8hEL6Bn+SQEM/DcjsSVhEryGiwJRNglVJjDGPrD31zPUEWuLBncOipepzvN4f3uss3GtApfpS0Em9nbzX72Jh8e6lvM+SBitT865AYjGgHLeW/5/BEm3703P7Vw29Tqog7emT8XroNv0kJP3yUy9iA==";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getCountry(X509Certificate)}
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	@Test
	public void testGetCountry() throws CertificateEncodingException
	{
		String expected;
		String actual;

		actual = CertificateExtensions.getCountry(certificate);
		expected = "";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getFingerprint(X509Certificate, HashAlgorithm)}
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 */
	@Test
	public void testGetFingerprint() throws CertificateEncodingException, NoSuchAlgorithmException
	{
		String expected;
		String actual;

		actual = CertificateExtensions.getFingerprint(certificate, HashAlgorithm.SHA1);
		expected = "98e12b1607890c76daa0b594be26616ceee93102";
		assertEquals(expected, actual);

		actual = CertificateExtensions.getFingerprint(certificate, HashAlgorithm.SHA_256);
		expected = "3a3dc338c7b444c3dd80e4f997d027a72451f9d5641783b3c810bf2d89bbd699";
		assertEquals(expected, actual);

		actual = CertificateExtensions.getFingerprint(certificate, HashAlgorithm.SHA_384);
		expected = "a44c1dc693670135c1abb13eb1a9472ab76059c29a7fb8b4a41ca605f3255fde7595374983ce7bc27633774d3c957026";
		assertEquals(expected, actual);

		actual = CertificateExtensions.getFingerprint(certificate, HashAlgorithm.SHA_512);
		expected = "8ea8310e1ed6f299e4de949a8094cde28bac3550bf4fd551283e346477fbba77b085adae6348df1a296b370fe56819baf4fdc31e43c42ce192cad4bbfc6829ae";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for
	 * {@link CertificateExtensions#getFirstValueOf(X509Certificate, org.bouncycastle.asn1.ASN1ObjectIdentifier)}
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	@Test
	public void testGetFirstValueOf() throws CertificateEncodingException
	{
		String expected;
		String actual;

		actual = CertificateExtensions.getFirstValueOf(certificate, BCStyle.CN);
		expected = "Test subject";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getIssuedBy(X509Certificate)}
	 */
	@Test
	public void testGetIssuedBy()
	{
		String expected;
		String actual;

		actual = CertificateExtensions.getIssuedBy(certificate);
		expected = "CN=Test subject";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getIssuedTo(X509Certificate)}
	 */
	@Test
	public void testGetIssuedTo()
	{
		String expected;
		String actual;

		actual = CertificateExtensions.getIssuedTo(certificate);
		expected = "CN=Test issue";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getLocality(X509Certificate)}
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	@Test
	public void testGetLocality() throws CertificateEncodingException
	{
		String expected;
		String actual;

		actual = CertificateExtensions.getLocality(certificate);
		expected = "";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getOrganization(X509Certificate)}
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	@Test
	public void testGetOrganization() throws CertificateEncodingException
	{
		String expected;
		String actual;

		actual = CertificateExtensions.getOrganization(certificate);
		expected = "";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getSignatureAlgorithm(X509Certificate)}
	 */
	@Test
	public void testGetSignatureAlgorithm()
	{
		String expected;
		String actual;

		actual = CertificateExtensions.getSignatureAlgorithm(certificate);
		expected = CompoundAlgorithm.SHA256_WITH_RSA.getAlgorithm();
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getValidFrom(X509Certificate)}
	 */
	@Test
	public void testGetValidFrom()
	{
		Date expected;
		Date actual;

		actual = CertificateExtensions.getValidFrom(certificate);
		expected = Date
			.from(ZonedDateTime.of(2016, 12, 31, 23, 0, 0, 0, ZoneId.of("UTC")).toInstant());
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getValidUntil(X509Certificate)}
	 */
	@Test
	public void testGetValidUntil()
	{
		Date expected;
		Date actual;

		actual = CertificateExtensions.getValidUntil(certificate);
		expected = Date
			.from(ZonedDateTime.of(2026, 12, 31, 23, 0, 0, 0, ZoneId.of("UTC")).toInstant());
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(CertificateExtensions.class);
	}

}
