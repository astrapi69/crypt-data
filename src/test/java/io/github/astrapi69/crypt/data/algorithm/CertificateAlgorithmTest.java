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
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.stream.Collectors;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.crypt.data.extension.CsvExtensions;
import io.github.astrapi69.crypt.data.extension.FileInitializerExtension;
import io.github.astrapi69.crypt.data.extension.LineAppender;
import io.github.astrapi69.crypt.data.factory.CertificateAlgorithmEntry;
import io.github.astrapi69.crypt.data.factory.CertificateTestDataFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.crypt.data.model.CertificateInfo;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.lang.thread.ThreadExtensions;
import lombok.NonNull;
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
	 * Tests and retrieves a list of valid signature algorithms that can be used to create an
	 * {@link X509Certificate} using the given certificate information.
	 *
	 * @param certificateInfo
	 *            the certificate information containing details like issuer, subject, etc.
	 * @param serviceName
	 *            the name of the service, typically "Signature"
	 * @return a list of valid signature algorithms that do not throw exceptions during certificate
	 *         creation
	 */
	public static List<String> getValidSignatureAlgorithms(final CertificateInfo certificateInfo,
		final @NonNull String serviceName)
	{
		Set<String> signatureAlgorithms = AlgorithmExtensions.getAlgorithms(serviceName);

		// Filter and test each algorithm, returning only those that are valid
		return signatureAlgorithms.stream()
			.filter(signatureAlgorithm -> isAlgorithmValidForCertificate(certificateInfo))
			.collect(Collectors.toList());
	}

	/**
	 * Tests whether a given signature algorithm can be used to successfully create an
	 * {@link X509Certificate}.
	 *
	 * @param certificateInfo
	 *            the certificate information containing details like issuer, subject, etc.
	 *
	 * @return true if the algorithm is valid and can be used to create the certificate, false
	 *         otherwise
	 */
	private static boolean isAlgorithmValidForCertificate(CertificateInfo certificateInfo)
	{
		try
		{
			// Attempt to create the certificate using the given signature algorithm
			X509Certificate certificate = newX509Certificate(certificateInfo);

			// If certificate creation is successful and no exception was thrown, the algorithm is
			// valid
			return certificate != null;
		}
		catch (OperatorCreationException | CertificateException | CertIOException e)
		{
			// If any exception occurs, the algorithm is not valid
			return false;
		}
	}


	@Test
	@Disabled
	public void testAllKeyPairGeneratorAlgorithmsWithSignature()
		throws IOException, InvocationTargetException, NoSuchMethodException, IllegalAccessException
	{

		File invalidSignatureAlgorithmsCsvFile = FileFactory.newFile(
			PathFinder.getSrcTestResourcesDir(), "invalid_certificate_signature_algorithms.csv");
		File validSignatureAlgorithmsCsvFile = FileFactory.newFile(
			PathFinder.getSrcTestResourcesDir(), "valid_certificate_signature_algorithms.csv");

		List<CertificateAlgorithmEntry> invalidSignatureAlgorithmEntries = FileInitializerExtension
			.inializeFile(invalidSignatureAlgorithmsCsvFile);
		List<CertificateAlgorithmEntry> validSignatureAlgorithmEntries = FileInitializerExtension
			.inializeFile(validSignatureAlgorithmsCsvFile);

		Set<String> keyPairGeneratorAlgorithms = AlgorithmExtensions
			.getAlgorithms("KeyPairGenerator");
		assertNotNull(keyPairGeneratorAlgorithms);

		Map<String, Set<Integer>> supportedKeySizesForKeyPairGenerator = AlgorithmExtensions
			.getSupportedAlgorithmsAndKeySizes("KeyPairGenerator", KeyPairGenerator.class,
				KeyPairGenerator::initialize, 1, 32768, 1);
		assertEquals(keyPairGeneratorAlgorithms.size(),
			supportedKeySizesForKeyPairGenerator.size());

		// Create a thread pool from the available processor cores
		int cores = Runtime.getRuntime().availableProcessors();
		int halfOfCores = Math.max(1, cores / 2);
		long timeoutSeconds = 60;
		ExecutorService executorService = Executors.newFixedThreadPool(halfOfCores);

		supportedKeySizesForKeyPairGenerator.entrySet().stream().forEach(entry -> {

			String keyPairAlgorithm = entry.getKey();
			Set<Integer> keySizes = entry.getValue();
			List<Integer> list = keySizes.stream().toList();

			Set<String> signatureAlgorithms = AlgorithmExtensions.getAlgorithms("Signature");
			Runnable task = () -> {
				try
				{
					KeyPair keyPair = KeyPairFactory.newKeyPair(keyPairAlgorithm, list.get(0));
					PrivateKey privateKey = keyPair.getPrivate();
					PublicKey publicKey = keyPair.getPublic();
					signatureAlgorithms.forEach(signatureAlgorithm -> {
						CertificateAlgorithmEntry certificateAlgorithmEntry = CertificateAlgorithmEntry
							.builder().keyPairAlgorithm(keyPairAlgorithm)
							.signatureAlgorithm(signatureAlgorithm).build();
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
							try
							{
								LineAppender.appendLines(validSignatureAlgorithmsCsvFile,
									certificateAlgorithmEntry.getKeyPairAlgorithm() + ","
										+ certificateAlgorithmEntry.getSignatureAlgorithm());
							}
							catch (IOException e)
							{
								log.log(Level.WARNING,
									"Entry '" + certificateAlgorithmEntry.getKeyPairAlgorithm()
										+ "," + certificateAlgorithmEntry.getSignatureAlgorithm()
										+ "' throws IOException",
									e);
							}
						}
						else
						{
							try
							{
								LineAppender.appendLines(invalidSignatureAlgorithmsCsvFile,
									certificateAlgorithmEntry.getKeyPairAlgorithm() + ","
										+ certificateAlgorithmEntry.getSignatureAlgorithm());
							}
							catch (IOException e)
							{
								log.log(Level.WARNING,
									"Entry '" + certificateAlgorithmEntry.getKeyPairAlgorithm()
										+ "," + certificateAlgorithmEntry.getSignatureAlgorithm()
										+ "' throws IOException",
									e);
							}
						}

					});


				}
				catch (NoSuchAlgorithmException | NoSuchProviderException e)
				{
					log.log(Level.WARNING, "Entry '" + keyPairAlgorithm + "' throws IOException",
						e);
				}
			};


			// Submit the task to the executor service
			executorService.submit(() -> {
				try
				{
					// Run task with a specified timeout
					ThreadExtensions.runWithTimeout(task, timeoutSeconds, TimeUnit.SECONDS);
				}
				catch (TimeoutException e)
				{
					log.log(Level.WARNING, "Algorithm throws: " + keyPairAlgorithm, e);
				}
			});
		});

	}

	private static List<CertificateAlgorithmEntry> inializeFile(
		File validSignatureAlgorithmsCsvFile) throws IOException
	{
		List<CertificateAlgorithmEntry> completedAlgorithmEntries;
		if (!validSignatureAlgorithmsCsvFile.exists())
		{
			completedAlgorithmEntries = ListFactory.newArrayList();
			LineAppender.appendLines(validSignatureAlgorithmsCsvFile,
				"keypair-algorithm,signature-algorithm");
		}
		else
		{
			completedAlgorithmEntries = CsvExtensions
				.readCertificateAlgorithmEntryFromCsv(validSignatureAlgorithmsCsvFile);
		}
		return completedAlgorithmEntries;
	}

}
