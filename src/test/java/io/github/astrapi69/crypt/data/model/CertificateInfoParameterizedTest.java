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
import java.security.Security;
import java.time.ZonedDateTime;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.mockito.junit.jupiter.MockitoExtension;

import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.crypt.api.key.KeyType;

/**
 * Test class for {@link CertificateInfo}
 */
@ExtendWith(MockitoExtension.class)
public class CertificateInfoParameterizedTest
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
	 * Parameterized test with CSV data
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/certificate_info_test_data.csv", numLinesToSkip = 1)
	void testParameterizedConstructor(String commonName, String countryCode, String location,
		String organisation, String organisationUnit, String state, String serialStr,
		String notBeforeStr, String notAfterStr, String signatureAlgorithm, String extensionId,
		String extensionValue)
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

		CertificateInfo certificateInfo;

		privateKeyInfo = KeyInfo.builder().keyType(KeyType.PRIVATE_KEY.getDisplayValue())
			.encoded(keyPair.getPrivate().getEncoded())
			.algorithm(keyPair.getPrivate().getAlgorithm()).build();
		publicKeyInfo = new KeyInfo(KeyType.PUBLIC_KEY.getDisplayValue(),
			keyPair.getPublic().getEncoded(), keyPair.getPublic().getAlgorithm());
		issuer = DistinguishedNameInfo.builder().commonName(commonName).countryCode(countryCode)
			.location(location).organisation(organisation).organisationUnit(organisationUnit)
			.state(state).build();
		subject = DistinguishedNameInfo.builder().commonName(commonName).countryCode(countryCode)
			.location(location).organisation(organisation).organisationUnit(organisationUnit)
			.state(state).build();

		serial = new BigInteger(serialStr);
		notBefore = ZonedDateTime.parse(notBeforeStr);
		notAfter = ZonedDateTime.parse(notAfterStr);
		validity = Validity.builder().notBefore(notBefore).notAfter(notAfter).build();
		extensionInfos = ArrayFactory.newArray(ExtensionInfo.builder().extensionId(extensionId)
			.critical(false).value(extensionValue).build());

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
}
