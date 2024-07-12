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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.key.KeyExtensions;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.create.FileInfo;
import io.github.astrapi69.file.search.PathFinder;

public class KeystoreCreator
{


	public static void main(String[] args) throws Exception
	{
		X509Certificate certificate;
		String distinguishedName;
		char[] password;

		password = "password".toCharArray();
		Security.addProvider(new BouncyCastleProvider());

		File keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new-keystore.jks");
		// Create DistinguishedNameInfo object with necessary information
		DistinguishedNameInfo distinguishedNameInfo = DistinguishedNameInfo.builder()
			.commonName("Test Server").countryCode("GB").location("London")
			.organisation("My Company").organisationUnit("IT Department").state("Greater London")
			.build();

		distinguishedName = distinguishedNameInfo.toRepresentableString();

		// Create KeyPairInfo object with necessary information
		KeyPairInfo keyPairInfo = KeyPairInfo.builder().algorithm("RSA").keySize(2048).build();
		FileInfo fileInfo = FileInfo.toFileInfo(keystoreFile);
		// Create KeyStoreInfo object with necessary information
		KeyStoreInfo keyStoreInfo = KeyStoreInfo.builder().fileInfo(fileInfo).type("JKS")
			.keystorePassword(password).build();

		// Generate Key Pair
		KeyPair keyPair = KeyPairInfo.toKeyPair(keyPairInfo);
		ExtensionInfo[] extensionInfos = ArrayFactory.newArray(ExtensionInfo.builder()
			.extensionId("1.3.6.1.5.5.7.3.2").critical(false).value("foo bar").build());
		// Create a self-signed certificate
		// cert = CertFactory.newX509CertificateV3(keyPair, issuer, serial, notBefore, notAfter,
		// subject, signatureAlgorithm);
		X509CertificateV1Info x509CertificateV1Info = X509CertificateV1Info.builder()
			.keyPairInfo(keyPairInfo).issuer(distinguishedNameInfo)
			.serial(new BigInteger(160, new SecureRandom()))
			.validity(Validity.builder().notBefore(ZonedDateTime.parse("2023-12-01T00:00:00Z"))
				.notAfter(ZonedDateTime.parse("2025-01-01T00:00:00Z")).build())
			.subject(distinguishedNameInfo).signatureAlgorithm("SHA256withRSA").build();
		X509CertificateV3Info x509CertificateV3Info = X509CertificateV3Info.builder()
			.certificateV1Info(x509CertificateV1Info).extensions(extensionInfos).build();
		// Generate Certificate
		certificate = CertFactory.newX509CertificateV3(x509CertificateV3Info);

		String base64 = KeyExtensions.toBase64(certificate.getEncoded());
		System.out.println(base64);

		// Convert KeyPair and Certificate to KeyModel
		KeyInfo privateKeyModel = KeyInfo.builder().keyType(KeyType.PRIVATE_KEY.getDisplayValue())
			.encoded(keyPair.getPrivate().getEncoded())
			.algorithm(keyPair.getPrivate().getAlgorithm()).build();

		KeyInfo publicKeyModel = KeyInfo.builder().keyType(KeyType.PUBLIC_KEY.getDisplayValue())
			.encoded(keyPair.getPublic().getEncoded()).algorithm(keyPair.getPublic().getAlgorithm())
			.build();

		KeyInfo certificateModel = KeyInfo.builder().keyType(KeyType.CERTIFICATE.getDisplayValue())
			.encoded(certificate.getEncoded()).algorithm(certificate.getSigAlgName()).build();

		// Create and save the KeyStore
		newKeystoreAndSaveForSsl(keyStoreInfo, privateKeyModel, certificateModel, "serverKey",
			password);
	}

	public static void newKeystoreAndSaveForSsl(KeyStoreInfo keyStoreInfo, KeyInfo privateKeyModel,
		KeyInfo certificateModel, String certificateAlias, char[] keyPassword)
		throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException
	{
		// Convert KeyModel to actual Key and Certificate objects
		PrivateKey privateKey = KeyInfoExtensions.toPrivateKey(privateKeyModel);
		X509Certificate certificate = KeyInfoExtensions.toX509Certificate(certificateModel);

		// Initialize a KeyStore and store the key pair and certificate
		KeyStore keyStore = KeyStoreInfo.toKeyStore(keyStoreInfo);

		keyStore.setKeyEntry(certificateAlias, privateKey, keyPassword,
			new java.security.cert.Certificate[] { certificate });
		File keystoreFile = FileInfo.toFile(keyStoreInfo.getFileInfo());
		try (FileOutputStream fos = new FileOutputStream(keystoreFile))
		{
			keyStore.store(fos, keyStoreInfo.getKeystorePassword());
		}
	}
}
