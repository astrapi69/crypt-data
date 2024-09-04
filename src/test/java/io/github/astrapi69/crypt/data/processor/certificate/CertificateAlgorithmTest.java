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
package io.github.astrapi69.crypt.data.processor.certificate;

import static io.github.astrapi69.crypt.data.factory.CertFactory.newX509Certificate;

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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.algorithm.AlgorithmExtensions;
import io.github.astrapi69.crypt.data.factory.CertificateTestDataFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.crypt.data.key.KeySizeExtensions;
import io.github.astrapi69.crypt.data.key.KeySizeInitializer;
import io.github.astrapi69.crypt.data.model.CertificateInfo;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.lang.thread.ThreadExtensions;
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

	@Test
	@Disabled("For creation for a valid map between keypair algorithm with signature algorithm")
	public void testAllKeyPairGeneratorAlgorithmsWithSignature()
		throws IOException, InvocationTargetException, NoSuchMethodException, IllegalAccessException
	{
		// Initialize CSV files for valid and invalid signature algorithms
		File invalidSignatureAlgorithmsCsvFile = FileFactory.newFile(
			PathFinder.getSrcTestResourcesDir(), "invalid_certificate_signature_algorithms.csv");
		File validSignatureAlgorithmsCsvFile = FileFactory.newFile(
			PathFinder.getSrcTestResourcesDir(),
			"valid_jdk_17_provider_bc_certificate_signature_algorithms.csv");

		Map<String, Set<Integer>> supportedKeySizesForKeyPairGenerator = AlgorithmExtensions
			.getSupportedAlgorithmsAndKeySizes("KeyPairGenerator", KeyPairGenerator.class,
				KeyPairGenerator::initialize, 1, 32768, 1);

		// Prepare a thread pool for parallel processing
		int cores = Runtime.getRuntime().availableProcessors();
		ExecutorService executorService = Executors.newFixedThreadPool(Math.max(1, cores / 2));
		long timeoutSeconds = 60;

		// Iterate over each KeyPairGenerator algorithm and its supported key sizes
		for (Map.Entry<String, Set<Integer>> entry : supportedKeySizesForKeyPairGenerator
			.entrySet())
		{
			String keyPairAlgorithm = entry.getKey();
			Set<Integer> keySizes = entry.getValue();

			CertificateAlgorithmEntryRunner task = new CertificateAlgorithmEntryRunner(
				keyPairAlgorithm, keySizes, validSignatureAlgorithmsCsvFile,
				invalidSignatureAlgorithmsCsvFile, true);

			// Retrieve available Signature algorithms
			Set<String> signatureAlgorithms = AlgorithmExtensions.getAlgorithms("Signature");

			// Process each algorithm in a separate task
			executorService.submit(() -> {
				try
				{
					// Run task with a specified timeout
					ThreadExtensions.runWithTimeout(task, timeoutSeconds, TimeUnit.SECONDS);
				}
				catch (TimeoutException e)
				{
					log.log(Level.WARNING,
						"KeyPair generation failed for algorithm: " + keyPairAlgorithm, e);
				}
			});
		}
		// Shutdown the executor service and wait for completion
		ThreadExtensions.shutdownExecutorService(executorService, timeoutSeconds,
			supportedKeySizesForKeyPairGenerator.size());
	}


	public static <T> Map<String, Set<String>> getSupportedSignatureAlgorithms(String serviceName,
		Class<T> generatorClass, KeySizeInitializer<T> initializer, int minSize, int maxSize,
		int increment) throws InvocationTargetException, NoSuchMethodException,
		IllegalAccessException, NoSuchAlgorithmException, NoSuchProviderException
	{

		Map<String, Set<String>> supportedSignatureAlgorithmsMap = new TreeMap<>();
		Set<String> algorithms = AlgorithmExtensions.getAlgorithms(serviceName);
		Set<String> signatureAlgorithms = AlgorithmExtensions.getAlgorithms("Signature");
		// Test with reduced range for quicker feedback
		for (String algorithm : algorithms)
		{
			Set<Integer> supportedKeySizes = KeySizeExtensions.getSupportedKeySizes(algorithm,
				generatorClass, initializer, minSize, maxSize, increment);
			Set<String> allValidSignatureAlgorithms = new TreeSet<>();


			if (!supportedKeySizes.isEmpty())
			{
				List<Integer> keySizesCopy = new ArrayList<>(supportedKeySizes);
				Integer keySize = keySizesCopy.get(0);
				KeyPair keyPair = KeyPairFactory.newKeyPair(algorithm, keySize);
				PrivateKey privateKey = keyPair.getPrivate();
				PublicKey publicKey = keyPair.getPublic();

				for (String signatureAlgorithm : signatureAlgorithms)
				{

					CertificateAlgorithmEntry certificateAlgorithmEntry = CertificateAlgorithmEntry
						.builder().keyPairAlgorithm(algorithm)
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
						supportedSignatureAlgorithmsMap.put(algorithm, allValidSignatureAlgorithms);
					}
				}
			}

		}

		return supportedSignatureAlgorithmsMap;
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
