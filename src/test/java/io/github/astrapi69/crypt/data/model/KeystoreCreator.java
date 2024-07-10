package io.github.astrapi69.crypt.data.model;

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

import io.github.astrapi69.crypt.data.key.KeyModelExtensions;
import io.github.astrapi69.crypt.data.model.KeyModel;
import io.github.astrapi69.crypt.data.model.KeyPairInfo;
import lombok.NonNull;

public class KeystoreCreator
{

	public static void main(String[] args) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		// Create KeyPairInfo object with necessary information
		KeyPairInfo keyPairInfo = KeyPairInfo.builder()
			// .distinguishedName(
			// "CN=Test Server, OU=IT Department, O=My Company, L=London, ST=Greater London, C=GB")
			.algorithm("RSA").keySize(2048)
			// .keystoreFilePath("keystore.jks")
			// .keystorePassword("password")
			// .keyPassword("password")
			// .validityDays(365)
			.build();

		// Generate Key Pair
		KeyPair keyPair = KeyPairInfo.newKeyPair(keyPairInfo);
		// TODO fix issues
		// // Generate Certificate
		// X509Certificate certificate = generateCertificate(keyPairInfo.getDistinguishedName(),
		// keyPair, keyPairInfo.getValidityDays(), "SHA256withRSA");
		//
		// // Convert KeyPair and Certificate to KeyModel
		// KeyModel privateKeyModel = KeyModelExtensions.toKeyModel(keyPair.getPrivate());
		// KeyModel publicKeyModel = KeyModelExtensions.toKeyModel(keyPair.getPublic());
		// KeyModel certificateModel = KeyModelExtensions.toKeyModel(certificate);
		//
		// // Create and save the KeyStore
		// createAndSaveKeystore(keyPairInfo, privateKeyModel, certificateModel);
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
	//
	// public static void createAndSaveKeystore(KeyPairInfo keyPairInfo, KeyModel privateKeyModel,
	// KeyModel certificateModel) throws Exception
	// {
	// KeyStore keyStore = KeyStore.getInstance("JKS");
	// keyStore.load(null, null);
	//
	// // Convert KeyModel to actual Key and Certificate objects
	// PrivateKey privateKey = KeyModelExtensions.toPrivateKey(privateKeyModel);
	// X509Certificate certificate = KeyModelExtensions.toX509Certificate(certificateModel);
	//
	// keyStore.setKeyEntry("serverKey", privateKey, keyPairInfo.getKeyPassword().toCharArray(),
	// new java.security.cert.Certificate[] { certificate });
	//
	// try (FileOutputStream fos = new FileOutputStream(keyPairInfo.getKeystoreFilePath()))
	// {
	// keyStore.store(fos, keyPairInfo.getKeystorePassword().toCharArray());
	// }
	//
	// System.out.println("Keystore created successfully at " + keyPairInfo.getKeystoreFilePath());
	// }
}
