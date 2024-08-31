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


import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.algorithm.AlgorithmExtensions;
import io.github.astrapi69.crypt.data.extension.FileInitializerExtension;
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
	@Disabled
	public void testAllKeyPairGeneratorAlgorithmsWithSignature()
		throws IOException, InvocationTargetException, NoSuchMethodException, IllegalAccessException
	{
		// Initialize CSV files for valid and invalid signature algorithms
		File invalidSignatureAlgorithmsCsvFile = FileFactory.newFile(
			PathFinder.getSrcTestResourcesDir(), "invalid_certificate_signature_algorithms.csv");
		File validSignatureAlgorithmsCsvFile = FileFactory.newFile(
			PathFinder.getSrcTestResourcesDir(), "valid_certificate_signature_algorithms.csv");

		List<CertificateAlgorithmEntry> invalidSignatureAlgorithmEntries = FileInitializerExtension
			.inializeFile(invalidSignatureAlgorithmsCsvFile);
		List<CertificateAlgorithmEntry> validSignatureAlgorithmEntries = FileInitializerExtension
			.inializeFile(validSignatureAlgorithmsCsvFile);

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

			CertificateAlgorithmEntryRunner task = new CertificateAlgorithmEntryRunner(null,
				keyPairAlgorithm, keySizes, validSignatureAlgorithmsCsvFile,
				invalidSignatureAlgorithmsCsvFile);

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
		shutdownExecutorService(executorService, timeoutSeconds);
	}

	private void shutdownExecutorService(ExecutorService executorService, long timeoutSeconds)
	{
		executorService.shutdown();
		try
		{
			if (!executorService.awaitTermination(timeoutSeconds * 2, TimeUnit.SECONDS))
			{
				executorService.shutdownNow();
			}
		}
		catch (InterruptedException e)
		{
			executorService.shutdownNow();
			Thread.currentThread().interrupt();
		}
	}

}
