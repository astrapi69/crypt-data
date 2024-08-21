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
package io.github.astrapi69.crypt.data.model;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.time.ZonedDateTime;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.meanbean.test.BeanTester;
import org.meanbean.test.BeanVerifier;
import org.mockito.junit.jupiter.MockitoExtension;

import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.crypt.api.key.KeyType;

/**
 * Test class for {@link CertificateInfo}
 */
@ExtendWith(MockitoExtension.class)
public class CertificateInfoTest
{

	private KeyPair keyPair;
	private KeyPairInfo keyPairInfo;

	@BeforeEach
	public void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		keyPairInfo = KeyPairInfo.builder().algorithm("RSA").keySize(2048).build();

		keyPair = KeyPairInfo.toKeyPair(keyPairInfo);
	}

	/**
	 * Test the {@link CertificateInfo} constructor
	 */
	@Test
	void testConstructor()
	{
		ExtensionInfo[] extensionInfos;
		KeyInfo privateKeyInfo;
		KeyInfo publicKeyInfo;
		DistinguishedNameInfo issuer;
		DistinguishedNameInfo subject;
		BigInteger serial;
		ZonedDateTime notBefore;
		ZonedDateTime notAfter;
		Validity validity;
		String signatureAlgorithm;

		CertificateInfo certificateInfo;

		privateKeyInfo = KeyInfo.builder().keyType(KeyType.PRIVATE_KEY.getDisplayValue())
			.encoded(keyPair.getPrivate().getEncoded())
			.algorithm(keyPair.getPrivate().getAlgorithm()).build();
		publicKeyInfo = new KeyInfo(KeyType.PUBLIC_KEY.getDisplayValue(),
			keyPair.getPublic().getEncoded(), keyPair.getPublic().getAlgorithm());
		issuer = DistinguishedNameInfo.builder().commonName("Issuer").countryCode("GB")
			.location("London").organisation("My Company").organisationUnit("IT Department")
			.state("Greater London").build();
		subject = DistinguishedNameInfo.builder().commonName("Subject").countryCode("GB")
			.location("London").organisation("My Company").organisationUnit("IT Department")
			.state("Greater London").build();

		serial = new BigInteger(160, new SecureRandom());
		notBefore = ZonedDateTime.now();
		notAfter = notBefore.plusYears(5L);
		validity = Validity.builder().notBefore(notBefore).notAfter(notAfter).build();
		signatureAlgorithm = "SHA256withRSA";
		extensionInfos = ArrayFactory.newArray(ExtensionInfo.builder()
			.extensionId("1.3.6.1.5.5.7.3.2").critical(false).value("foo bar").build());

		certificateInfo = CertificateInfo.builder().privateKeyInfo(privateKeyInfo)
			.publicKeyInfo(publicKeyInfo).issuer(issuer).subject(subject).serial(serial)
			.validity(validity).signatureAlgorithm(signatureAlgorithm).extensions(extensionInfos)
			.build();

		assertNotNull(certificateInfo);
		assertEquals(privateKeyInfo, certificateInfo.getPrivateKeyInfo());
		assertEquals(publicKeyInfo, certificateInfo.getPublicKeyInfo());
		assertEquals(issuer, certificateInfo.getIssuer());
		assertEquals(serial, certificateInfo.getSerial());
		assertEquals(validity, certificateInfo.getValidity());
		assertEquals(subject, certificateInfo.getSubject());
		assertEquals(signatureAlgorithm, certificateInfo.getSignatureAlgorithm());
		assertEquals(extensionInfos, certificateInfo.getExtensions());
	}


	/**
	 * Test method for {@link CertificateInfo} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanVerifier.forClass(CertificateInfo.class).editSettings()
			.registerFactory(ExtensionInfo.class, () -> {
				return ExtensionInfo.builder().extensionId("1.2.3.4.5.6.7").critical(true)
					.value("testValue").build();
			}).registerFactory(DistinguishedNameInfo.class, () -> {
				return DistinguishedNameInfo.builder().countryCode("US").state("California")
					.location("San Francisco").organisation("MyOrg").organisationUnit("MyUnit")
					.commonName("John Doe").build();
			}).registerFactory(DistinguishedNameInfo.class, () -> {
				return DistinguishedNameInfo.builder().countryCode("US").state("California")
					.location("San Francisco").organisation("MyOrg").organisationUnit("MyUnit")
					.commonName("John Doe").build();
			}).registerFactory(Validity.class, () -> {
				return Validity.builder().notBefore(ZonedDateTime.parse("2023-12-01T00:00:00Z"))
					.notAfter(ZonedDateTime.parse("2025-01-01T00:00:00Z")).build();
			}).registerFactory(CertificateInfo.class, () -> {

				ExtensionInfo[] extensionInfos;
				KeyInfo privateKeyInfo;
				KeyInfo publicKeyInfo;
				DistinguishedNameInfo issuer;
				DistinguishedNameInfo subject;
				BigInteger serial;
				ZonedDateTime notBefore;
				ZonedDateTime notAfter;
				Validity validity;
				String signatureAlgorithm;

				CertificateInfo certificateInfo;

				privateKeyInfo = KeyInfo.builder().keyType(KeyType.PRIVATE_KEY.getDisplayValue())
					.encoded(keyPair.getPrivate().getEncoded())
					.algorithm(keyPair.getPrivate().getAlgorithm()).build();
				publicKeyInfo = new KeyInfo(KeyType.PUBLIC_KEY.getDisplayValue(),
					keyPair.getPublic().getEncoded(), keyPair.getPublic().getAlgorithm());
				issuer = DistinguishedNameInfo.builder().commonName("Issuer").countryCode("GB")
					.location("London").organisation("My Company").organisationUnit("IT Department")
					.state("Greater London").build();
				subject = DistinguishedNameInfo.builder().commonName("Subject").countryCode("GB")
					.location("London").organisation("My Company").organisationUnit("IT Department")
					.state("Greater London").build();

				serial = new BigInteger(160, new SecureRandom());
				notBefore = ZonedDateTime.now();
				notAfter = notBefore.plusYears(5L);
				validity = Validity.builder().notBefore(notBefore).notAfter(notAfter).build();
				signatureAlgorithm = "SHA256withRSA";
				extensionInfos = ArrayFactory.newArray(ExtensionInfo.builder()
					.extensionId("1.3.6.1.5.5.7.3.2").critical(false).value("foo bar").build());

				certificateInfo = CertificateInfo.builder().privateKeyInfo(privateKeyInfo)
					.publicKeyInfo(publicKeyInfo).issuer(issuer).subject(subject).serial(serial)
					.validity(validity).signatureAlgorithm(signatureAlgorithm)
					.extensions(extensionInfos).build();
				return certificateInfo;
			}).registerFactory(KeyInfo.class, () -> {
				return KeyInfo.builder().keyType(KeyType.PRIVATE_KEY.getDisplayValue())
					.encoded(keyPair.getPrivate().getEncoded())
					.algorithm(keyPair.getPrivate().getAlgorithm()).build();
			}).edited().verify();
	}


}
