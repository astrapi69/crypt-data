package io.github.astrapi69.crypt.data.algorithm;

import static io.github.astrapi69.crypt.data.factory.CertFactory.newX509Certificate;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import io.github.astrapi69.crypt.data.extension.FileInitializerExtension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.extension.LineAppender;
import io.github.astrapi69.crypt.data.factory.CertificateAlgorithmEntry;
import io.github.astrapi69.crypt.data.factory.CertificateTestDataFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.crypt.data.model.CertificateInfo;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;
import lombok.extern.java.Log;

/**
 * Utility class to resolve and test appropriate signature algorithms for X.509 certificate
 * creation.
 */
@Log
public class CertificateAlgorithmTest
{

	@BeforeEach
	public void setUp()
	{
		// Ensuring that some default algorithms are registered for the tests
		Security.addProvider(new BouncyCastleProvider());
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





	@Test
// @Disabled
	public void testAllKeyPairGeneratorAlgorithmsWithSignature()
			throws IOException, InvocationTargetException, NoSuchMethodException, IllegalAccessException {

		// Initialize CSV files for valid and invalid signature algorithms
		File invalidSignatureAlgorithmsCsvFile = FileFactory.newFile(
				PathFinder.getSrcTestResourcesDir(), "invalid_certificate_signature_algorithms.csv");
		File validSignatureAlgorithmsCsvFile = FileFactory.newFile(
				PathFinder.getSrcTestResourcesDir(), "valid_certificate_signature_algorithms.csv");

		List<CertificateAlgorithmEntry> invalidSignatureAlgorithmEntries = FileInitializerExtension.inializeFile(
				invalidSignatureAlgorithmsCsvFile);
		List<CertificateAlgorithmEntry> validSignatureAlgorithmEntries = FileInitializerExtension.inializeFile(
				validSignatureAlgorithmsCsvFile);

		// Retrieve available KeyPairGenerator algorithms and their supported key sizes
		Set<String> keyPairGeneratorAlgorithms = AlgorithmExtensions.getAlgorithms("KeyPairGenerator");
		assertNotNull(keyPairGeneratorAlgorithms);

		Map<String, Set<Integer>> supportedKeySizesForKeyPairGenerator = AlgorithmExtensions
				.getSupportedAlgorithmsAndKeySizes("KeyPairGenerator", KeyPairGenerator.class,
						KeyPairGenerator::initialize, 1, 32768, 1);
		assertEquals(keyPairGeneratorAlgorithms.size(), supportedKeySizesForKeyPairGenerator.size());

		// Prepare a thread pool for parallel processing
		int cores = Runtime.getRuntime().availableProcessors();
		ExecutorService executorService = Executors.newFixedThreadPool(Math.max(1, cores / 2));
		long timeoutSeconds = 60;

		// Iterate over each KeyPairGenerator algorithm and its supported key sizes
		for (Map.Entry<String, Set<Integer>> entry : supportedKeySizesForKeyPairGenerator.entrySet()) {
			String keyPairAlgorithm = entry.getKey();
			Set<Integer> keySizes = entry.getValue();

			// Retrieve available Signature algorithms
			Set<String> signatureAlgorithms = AlgorithmExtensions.getAlgorithms("Signature");

			// Process each algorithm in a separate task
			executorService.submit(() -> {
				try {
					for (Integer keySize : keySizes) {
						KeyPair keyPair = KeyPairFactory.newKeyPair(keyPairAlgorithm, keySize);
						PrivateKey privateKey = keyPair.getPrivate();
						PublicKey publicKey = keyPair.getPublic();

						for (String signatureAlgorithm : signatureAlgorithms) {
							processSignatureAlgorithm(keyPairAlgorithm, signatureAlgorithm, keySize,
									privateKey, publicKey, validSignatureAlgorithmsCsvFile,
									invalidSignatureAlgorithmsCsvFile);
						}
					}
				} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
					log.log(Level.WARNING, "KeyPair generation failed for algorithm: " + keyPairAlgorithm, e);
				}
			});
		}

		// Shutdown the executor service and wait for completion
		shutdownExecutorService(executorService, timeoutSeconds);
	}






//
//
//	@Test
//	// @Disabled
//	public void testAllKeyPairGeneratorAlgorithmsWithSignature()
//		throws IOException, InvocationTargetException, NoSuchMethodException, IllegalAccessException
//	{
//
//		File invalidSignatureAlgorithmsCsvFile = FileFactory.newFile(
//			PathFinder.getSrcTestResourcesDir(), "invalid_certificate_signature_algorithms.csv");
//		File validSignatureAlgorithmsCsvFile = FileFactory.newFile(
//			PathFinder.getSrcTestResourcesDir(), "valid_certificate_signature_algorithms.csv");
//
//		List<CertificateAlgorithmEntry> invalidSignatureAlgorithmEntries = FileInitializerExtension.inializeFile(
//			invalidSignatureAlgorithmsCsvFile);
//		List<CertificateAlgorithmEntry> validSignatureAlgorithmEntries = FileInitializerExtension.inializeFile(
//			validSignatureAlgorithmsCsvFile);
//
//		Set<String> keyPairGeneratorAlgorithms = AlgorithmExtensions
//			.getAlgorithms("KeyPairGenerator");
//		assertNotNull(keyPairGeneratorAlgorithms);
//
//		Map<String, Set<Integer>> supportedKeySizesForKeyPairGenerator = AlgorithmExtensions
//			.getSupportedAlgorithmsAndKeySizes("KeyPairGenerator", KeyPairGenerator.class,
//				KeyPairGenerator::initialize, 1, 32768, 1);
//		assertEquals(keyPairGeneratorAlgorithms.size(),
//			supportedKeySizesForKeyPairGenerator.size());
//
//		// Create a thread pool from the available processor cores
//		int cores = Runtime.getRuntime().availableProcessors();
//		int halfOfCores = Math.max(1, cores / 2);
//		long timeoutSeconds = 60;
//		ExecutorService executorService = Executors.newFixedThreadPool(halfOfCores);
//
//		supportedKeySizesForKeyPairGenerator.forEach((keyPairAlgorithm, keySizes) -> {
//
//			Set<String> signatureAlgorithms = AlgorithmExtensions.getAlgorithms("Signature");
//
//			Runnable task = () -> {
//				try
//				{
//					Iterator<Integer> keySizeIterator = keySizes.iterator();
//					if (!keySizeIterator.hasNext())
//					{
//						log.log(Level.WARNING,
//							"No valid key sizes found for algorithm: " + keyPairAlgorithm);
//						return;
//					}
//					int keySize = keySizeIterator.next();
//					KeyPair keyPair = KeyPairFactory.newKeyPair(keyPairAlgorithm, keySize);
//					PrivateKey privateKey = keyPair.getPrivate();
//					PublicKey publicKey = keyPair.getPublic();
//
//					signatureAlgorithms.forEach(signatureAlgorithm -> {
//						CertificateAlgorithmEntry certificateAlgorithmEntry = CertificateAlgorithmEntry
//							.builder().keyPairAlgorithm(keyPairAlgorithm)
//							.signatureAlgorithm(signatureAlgorithm).build();
//
//						CertificateInfo certificateInfo = CertificateInfo.builder()
//							.privateKeyInfo(KeyInfoExtensions.toKeyInfo(privateKey))
//							.publicKeyInfo(KeyInfoExtensions.toKeyInfo(publicKey))
//							.issuer(CertificateTestDataFactory.newIssuerDistinguishedNameInfo())
//							.subject(CertificateTestDataFactory.newSubjectDistinguishedNameInfo())
//							.serial(CertificateTestDataFactory.newSerialNumber())
//							.validity(CertificateTestDataFactory.newValidity())
//							.signatureAlgorithm(signatureAlgorithm).version(3)
//							.extensions(CertificateTestDataFactory.newExtensionInfos()).build();
//
//						if (isAlgorithmValidForCertificate(certificateInfo))
//						{
//							try
//							{
//								LineAppender.appendLines(validSignatureAlgorithmsCsvFile,
//									certificateAlgorithmEntry.getKeyPairAlgorithm() + ","
//										+ certificateAlgorithmEntry.getSignatureAlgorithm());
//							}
//							catch (IOException e)
//							{
//								log.log(Level.WARNING,
//									"IOException while appending valid entry: "
//										+ certificateAlgorithmEntry.getKeyPairAlgorithm() + ","
//										+ certificateAlgorithmEntry.getSignatureAlgorithm(),
//									e);
//							}
//						}
//						else
//						{
//							try
//							{
//								LineAppender.appendLines(invalidSignatureAlgorithmsCsvFile,
//									certificateAlgorithmEntry.getKeyPairAlgorithm() + ","
//										+ certificateAlgorithmEntry.getSignatureAlgorithm());
//							}
//							catch (IOException e)
//							{
//								log.log(Level.WARNING,
//									"IOException while appending invalid entry: "
//										+ certificateAlgorithmEntry.getKeyPairAlgorithm() + ","
//										+ certificateAlgorithmEntry.getSignatureAlgorithm(),
//									e);
//							}
//						}
//					});
//
//				}
//				catch (NoSuchAlgorithmException | NoSuchProviderException e)
//				{
//					log.log(Level.WARNING,
//						"KeyPair generation failed for algorithm: " + keyPairAlgorithm, e);
//				}
//			};
//
//			// Submit the task to the executor service
//			executorService.submit(() -> {
//				try
//				{
//					// Run task with a specified timeout
//					ThreadExtensions.runWithTimeout(task, timeoutSeconds, TimeUnit.SECONDS);
//				}
//				catch (TimeoutException e)
//				{
//					log.log(Level.WARNING, "Task timed out for algorithm: " + keyPairAlgorithm, e);
//				}
//			});
//		});
//
//		// Shutdown the executor service
//		executorService.shutdown();
//		try
//		{
//			if (!executorService.awaitTermination(60, TimeUnit.SECONDS))
//			{
//				executorService.shutdownNow();
//			}
//		}
//		catch (InterruptedException e)
//		{
//			executorService.shutdownNow();
//			Thread.currentThread().interrupt();
//		}
//	}

	private void processSignatureAlgorithm(String keyPairAlgorithm, String signatureAlgorithm,
										   int keySize, PrivateKey privateKey, PublicKey publicKey, File validSignatureAlgorithmsCsvFile,
										   File invalidSignatureAlgorithmsCsvFile) {

		CertificateAlgorithmEntry certificateAlgorithmEntry = CertificateAlgorithmEntry.builder()
				.keyPairAlgorithm(keyPairAlgorithm)
				.signatureAlgorithm(signatureAlgorithm)
				.build();

		CertificateInfo certificateInfo = CertificateInfo.builder()
				.privateKeyInfo(KeyInfoExtensions.toKeyInfo(privateKey))
				.publicKeyInfo(KeyInfoExtensions.toKeyInfo(publicKey))
				.issuer(CertificateTestDataFactory.newIssuerDistinguishedNameInfo())
				.subject(CertificateTestDataFactory.newSubjectDistinguishedNameInfo())
				.serial(CertificateTestDataFactory.newSerialNumber())
				.validity(CertificateTestDataFactory.newValidity())
				.signatureAlgorithm(signatureAlgorithm)
				.version(3)
				.extensions(CertificateTestDataFactory.newExtensionInfos())
				.build();

		if (isAlgorithmValidForCertificate(certificateInfo)) {
			appendToFile(validSignatureAlgorithmsCsvFile, certificateAlgorithmEntry);
		} else {
			appendToFile(invalidSignatureAlgorithmsCsvFile, certificateAlgorithmEntry);
		}
	}


	private void appendToFile(File file, CertificateAlgorithmEntry entry) {
		try {
			LineAppender.appendLines(file, entry.getKeyPairAlgorithm() + "," + entry.getSignatureAlgorithm());
		} catch (IOException e) {
			log.log(Level.WARNING, "IOException while appending entry to file: " + file.getName(), e);
		}
	}

	private void shutdownExecutorService(ExecutorService executorService, long timeoutSeconds) {
		executorService.shutdown();
		try {
			if (!executorService.awaitTermination(timeoutSeconds * 2, TimeUnit.SECONDS)) {
				executorService.shutdownNow();
			}
		} catch (InterruptedException e) {
			executorService.shutdownNow();
			Thread.currentThread().interrupt();
		}
	}
}
