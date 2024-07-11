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
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.create.FileInfo;
import io.github.astrapi69.file.search.PathFinder;

public class KeystoreCreator
{
	public static void main(String[] args) throws Exception
	{
		X509Certificate cert;
		String dn;
		char[] password;

		password = "password".toCharArray();
		Security.addProvider(new BouncyCastleProvider());

		File keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new-keystore.jks");
		// Create DistinguishedNameInfo object with necessary information
		DistinguishedNameInfo dnInfo = DistinguishedNameInfo.builder().commonName("Test Server")
			.countryCode("GB").location("London").organisation("My Company")
			.organisationUnit("IT Department").state("Greater London").build();

		dn = dnInfo.toRepresentableString();

		// Create KeyPairInfo object with necessary information
		KeyPairInfo keyPairInfo = KeyPairInfo.builder().algorithm("RSA").keySize(2048).build();

		// Create KeyStoreInfo object with necessary information
		KeyStoreInfo keyStoreInfo = KeyStoreInfo.builder()
			.fileInfo(FileInfo.toFileInfo(keystoreFile)).type("JKS").keystorePassword(password)
			.build();

		// Generate Key Pair
		KeyPair keyPair = KeyPairInfo.newKeyPair(keyPairInfo);
		// Create a self-signed certificate
		// cert = CertFactory.newX509CertificateV3(keyPair, issuer, serial, notBefore, notAfter,
		// subject, signatureAlgorithm);

		// Generate Certificate
		X509Certificate certificate = generateCertificate(
			DistinguishedNameInfo.toRepresentableString(dnInfo), keyPair, 365, "SHA256withRSA");

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
		createAndSaveKeystoreForSsl(keyStoreInfo, privateKeyModel, certificateModel, "serverKey",
			password);
	}

	public static KeyPair generateKeyPair(String algorithm, int keySize) throws Exception
	{
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm, "BC");
		keyPairGen.initialize(keySize);
		return keyPairGen.generateKeyPair();
	}

	public static X509Certificate generateCertificate(String dn, KeyPair pair, int days,
		String algorithm) throws Exception
	{
		long now = System.currentTimeMillis();
		Date startDate = new Date(now);
		Date endDate = new Date(now + days * 86400000L);

		BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // unique serial number

		ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm)
			.build(pair.getPrivate());

		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
			new org.bouncycastle.asn1.x500.X500Name(dn), certSerialNumber, startDate, endDate,
			new org.bouncycastle.asn1.x500.X500Name(dn), pair.getPublic());

		return new JcaX509CertificateConverter().setProvider("BC")
			.getCertificate(certBuilder.build(contentSigner));
	}

	public static void createAndSaveKeystoreForSsl(KeyStoreInfo keyStoreInfo,
		KeyInfo privateKeyModel, KeyInfo certificateModel, String alias, char[] keyPassword)
		throws Exception
	{
		KeyStore keyStore = KeyStore.getInstance(keyStoreInfo.getType());
		keyStore.load(null, null);

		// Convert KeyModel to actual Key and Certificate objects
		PrivateKey privateKey = KeyInfoExtensions.toPrivateKey(privateKeyModel);
		X509Certificate certificate = KeyInfoExtensions.toX509Certificate(certificateModel);

		keyStore.setKeyEntry(alias, privateKey, keyPassword,
			new java.security.cert.Certificate[] { certificate });

		try (FileOutputStream fos = new FileOutputStream(keyStoreInfo.getFileInfo().getPath()))
		{
			keyStore.store(fos, keyStoreInfo.getKeystorePassword());
		}

		System.out
			.println("Keystore created successfully at " + keyStoreInfo.getFileInfo().getPath());
	}
}
