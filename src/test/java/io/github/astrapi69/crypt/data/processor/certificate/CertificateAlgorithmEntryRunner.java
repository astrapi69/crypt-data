package io.github.astrapi69.crypt.data.processor.certificate;

import static io.github.astrapi69.crypt.data.factory.CertFactory.newX509Certificate;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.logging.Level;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

import io.github.astrapi69.crypt.data.algorithm.AlgorithmExtensions;
import io.github.astrapi69.crypt.data.extension.LineAppender;
import io.github.astrapi69.crypt.data.factory.CertificateTestDataFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.crypt.data.model.CertificateInfo;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;
import lombok.extern.java.Log;

@Log
@Getter
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CertificateAlgorithmEntryRunner implements Runnable
{
	CertificateAlgorithmEntry certificateAlgorithmEntry;
	String keyPairAlgorithm;
	Set<Integer> keySizes;
	Set<String> signatureAlgorithms;
	File validSignatureAlgorithmsCsvFile;
	File invalidSignatureAlgorithmsCsvFile;

	public CertificateAlgorithmEntryRunner(
		final @NonNull CertificateAlgorithmEntry certificateAlgorithmEntry,
		final @NonNull String keyPairAlgorithm, final @NonNull Set<Integer> keySizes,
		final @NonNull File validSignatureAlgorithmsCsvFile,
		final @NonNull File invalidSignatureAlgorithmsCsvFile)
	{
		this.certificateAlgorithmEntry = certificateAlgorithmEntry;
		this.keyPairAlgorithm = keyPairAlgorithm;
		this.keySizes = keySizes;
		this.signatureAlgorithms = AlgorithmExtensions.getAlgorithms("Signature");
		this.validSignatureAlgorithmsCsvFile = validSignatureAlgorithmsCsvFile;
		this.invalidSignatureAlgorithmsCsvFile = invalidSignatureAlgorithmsCsvFile;
	}

	@Override
	public void run()
	{
		try
		{
			for (Integer keySize : keySizes)
			{
				KeyPair keyPair = KeyPairFactory.newKeyPair(keyPairAlgorithm, keySize);
				PrivateKey privateKey = keyPair.getPrivate();
				PublicKey publicKey = keyPair.getPublic();

				for (String signatureAlgorithm : signatureAlgorithms)
				{
					processSignatureAlgorithm(keyPairAlgorithm, signatureAlgorithm, privateKey,
						publicKey, validSignatureAlgorithmsCsvFile,
						invalidSignatureAlgorithmsCsvFile);
				}
			}
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e)
		{
			log.log(Level.WARNING, "KeyPair generation failed for algorithm: " + keyPairAlgorithm,
				e);
		}
	}

	private void processSignatureAlgorithm(String keyPairAlgorithm, String signatureAlgorithm,
		PrivateKey privateKey, PublicKey publicKey, File validSignatureAlgorithmsCsvFile,
		File invalidSignatureAlgorithmsCsvFile)
	{

		CertificateAlgorithmEntry certificateAlgorithmEntry = CertificateAlgorithmEntry.builder()
			.keyPairAlgorithm(keyPairAlgorithm).signatureAlgorithm(signatureAlgorithm).build();

		CertificateInfo certificateInfo = CertificateInfo.builder()
			.privateKeyInfo(KeyInfoExtensions.toKeyInfo(privateKey))
			.publicKeyInfo(KeyInfoExtensions.toKeyInfo(publicKey))
			.issuer(CertificateTestDataFactory.newIssuerDistinguishedNameInfo())
			.subject(CertificateTestDataFactory.newSubjectDistinguishedNameInfo())
			.serial(CertificateTestDataFactory.newSerialNumber())
			.validity(CertificateTestDataFactory.newValidity())
			.signatureAlgorithm(signatureAlgorithm).version(3)
			.extensions(CertificateTestDataFactory.newExtensionInfos()).build();

		if (isAlgorithmValidForCertificate(certificateInfo))
		{
			appendToFile(validSignatureAlgorithmsCsvFile, certificateAlgorithmEntry);
		}
		else
		{
			appendToFile(invalidSignatureAlgorithmsCsvFile, certificateAlgorithmEntry);
		}
	}

	private void appendToFile(File file, CertificateAlgorithmEntry entry)
	{
		try
		{
			LineAppender.appendLines(file,
				entry.getKeyPairAlgorithm() + "," + entry.getSignatureAlgorithm());
		}
		catch (IOException e)
		{
			log.log(Level.WARNING, "IOException while appending entry to file: " + file.getName(),
				e);
		}
	}

	/**
	 * Tests whether a given signature algorithm can be used to successfully create an
	 * {@link X509Certificate}.
	 *
	 * @param certificateInfo
	 *            the certificate information containing details like issuer, subject, etc.
	 * @return true if the algorithm is valid and can be used to create the certificate, false
	 *         otherwise
	 */
	public static boolean isAlgorithmValidForCertificate(CertificateInfo certificateInfo)
	{
		try
		{
			// Attempt to create the certificate using the given signature algorithm
			X509Certificate certificate = newX509Certificate(certificateInfo);

			// If certificate creation is successful and no exception was thrown, the algorithm is
			// valid
			return certificate != null;
		}
		catch (IllegalArgumentException e)
		{
			// Handle specific cases where the signature type is unknown
			log.log(Level.WARNING,
				"Unknown signature type: " + certificateInfo.getSignatureAlgorithm(), e);
			return false;
		}
		catch (OperatorCreationException | CertificateException | CertIOException e)
		{
			log.log(Level.WARNING, "Certificate creation failed for algorithm: "
				+ certificateInfo.getSignatureAlgorithm(), e);
			return false;
		}
	}
}
