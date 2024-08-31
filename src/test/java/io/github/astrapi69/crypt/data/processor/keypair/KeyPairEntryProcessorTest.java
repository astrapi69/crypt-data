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
package io.github.astrapi69.crypt.data.processor.keypair;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
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

import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.crypt.data.algorithm.AlgorithmExtensions;
import io.github.astrapi69.crypt.data.extension.CsvExtensions;
import io.github.astrapi69.crypt.data.extension.FileInitializerExtension;
import io.github.astrapi69.crypt.data.extension.LineAppender;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.KeySizeExtensions;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.lang.thread.ThreadExtensions;
import lombok.extern.java.Log;

@Log
public class KeyPairEntryProcessorTest
{

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@BeforeEach
	protected void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Test method for with all algorithms
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	@Test
	@Disabled
	public void testWithAllExistingAlgorithms() throws IOException
	{
		List<KeyPairEntry> validKeypairEntries;
		List<KeyPairEntry> testKeypairEntries;
		List<KeyPairEntry> invalidKeyPairEntries;

		File validCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new_valid_key_pair_algorithms.csv");
		File testKeypairAlgorithmsCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"test_key_pair_algorithms.csv");
		File invalidCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"invalid_key_pair_algorithms.csv");

		invalidKeyPairEntries = FileInitializerExtension.getKeyPairEntries(invalidCsvFile);
		validKeypairEntries = FileInitializerExtension.getKeyPairEntries(validCsvFile);
		testKeypairEntries = FileInitializerExtension
			.getKeyPairEntries(testKeypairAlgorithmsCsvFile);
		testKeypairEntries.removeAll(invalidKeyPairEntries);
		testKeypairEntries.removeAll(validKeypairEntries);

		// Use the new method to process the key pair entries
		processKeyPairEntries(testKeypairEntries, validCsvFile, invalidCsvFile, 60);
	}

	public void processKeyPairEntries(List<KeyPairEntry> testKeypairEntries, File validCsvFile,
		File invalidCsvFile, long timeoutSeconds)
	{
		// Create a thread pool from the available processor cores
		int cores = Runtime.getRuntime().availableProcessors();

		int halfOfCores = Math.max(1, cores / 2);
		ExecutorService executorService = Executors.newFixedThreadPool(halfOfCores);

		testKeypairEntries.forEach(keyPairEntry -> {

			KeyPairEntryRunner task = new KeyPairEntryRunner(keyPairEntry, validCsvFile,
				invalidCsvFile);

			// Submit the task to the executor service
			executorService.submit(() -> {
				try
				{
					// Run task with a specified timeout
					ThreadExtensions.runWithTimeout(task, timeoutSeconds, TimeUnit.SECONDS);
				}
				catch (TimeoutException e)
				{
					log.log(Level.WARNING, "Algorithm throws: " + keyPairEntry.getAlgorithm(), e);
					try
					{
						LineAppender.appendLines(invalidCsvFile,
							keyPairEntry.getAlgorithm() + "," + keyPairEntry.getKeySize());
					}
					catch (IOException ex)
					{
						log.log(
							Level.WARNING, "Algorithm did not save to file "
								+ invalidCsvFile.getName() + " : " + keyPairEntry.getAlgorithm(),
							ex);
					}
				}
			});
		});

		// Shutdown the executor service after submitting all tasks
		executorService.shutdown();
		try
		{
			// Wait for all tasks to complete or timeout
			if (!executorService.awaitTermination(timeoutSeconds * testKeypairEntries.size(),
				TimeUnit.SECONDS))
			{
				executorService.shutdownNow();
			}
		}
		catch (InterruptedException e)
		{
			executorService.shutdownNow();
		}
	}

	/**
	 * Test method for with all algorithms
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	@Test
	@Disabled
	public void testWithAllAlgorithms() throws IOException
	{
		List<KeyPairEntry> validKeyPairEntries;
		List<KeyPairEntry> invalidKeyPairEntries;
		File validCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"valid_key_pair_algorithms.csv");
		File invalidCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"invalid_key_pair_algorithms.csv");
		if (!invalidCsvFile.exists())
		{
			invalidKeyPairEntries = null;
			LineAppender.appendLines(invalidCsvFile, "algorithm,keysize");
		}
		else
		{
			invalidKeyPairEntries = CsvExtensions.readKeyPairEntriesFromCsv(invalidCsvFile);
		}

		if (!validCsvFile.exists())
		{
			validKeyPairEntries = null;
			LineAppender.appendLines(validCsvFile, "algorithm,keysize");
		}
		else
		{
			validKeyPairEntries = CsvExtensions.readKeyPairEntriesFromCsv(validCsvFile);
		}

		Map<String, List<Integer>> algorithmKeysizeMap = new HashMap<>();

		Set<String> keyPairGeneratorAlgorithms = AlgorithmExtensions
			.getAlgorithms("KeyPairGenerator");
		keyPairGeneratorAlgorithms.forEach(algorithm -> {
			try
			{
				Set<Integer> supportedKeySizes = KeySizeExtensions
					.getSupportedKeySizesForKeyPairGenerator(algorithm);
				List<Integer> keySizes = new ArrayList<>(supportedKeySizes);

				keySizes.forEach(keysize -> {
					try
					{
						KeyPairEntry currentEntry = KeyPairEntry.builder().keySize(keysize)
							.algorithm(algorithm).build();
						boolean containsInValidAlgorithm = validKeyPairEntries
							.contains(currentEntry);
						boolean containsInInvalidAlgorithm = invalidKeyPairEntries
							.contains(currentEntry);
						if (!containsInValidAlgorithm && !containsInInvalidAlgorithm)
						{
							System.out
								.println("algorithm: " + algorithm + " , keysize: " + keysize);
							KeyPairFactory.newKeyPair(algorithm, keysize);

							LineAppender.appendLines(validCsvFile, algorithm + "," + keysize);
							if (algorithmKeysizeMap.containsKey(algorithm))
							{
								algorithmKeysizeMap.get(algorithm).add(keysize);
							}
							else
							{
								algorithmKeysizeMap.put(algorithm,
									ListFactory.newArrayList(keysize));
							}
						}
						else
						{
							System.out.println(
								"algorithm: " + algorithm + " , keysize: " + keysize + " exists");
						}
					}
					catch (NoSuchAlgorithmException e)
					{
						log.log(Level.WARNING, "Algorithm throws: " + algorithm, e);
					}
					catch (NoSuchProviderException e)
					{
						log.log(Level.WARNING, "Algorithm throws: " + algorithm, e);
					}
					catch (Exception e)
					{
						log.log(Level.WARNING, "Algorithm throws: " + algorithm, e);
					}
				});

			}
			catch (Exception e)
			{
				log.log(Level.WARNING, "Algorithm throws: " + algorithm, e);
			}
		});
		algorithmKeysizeMap.forEach((key, value) -> {
			System.out.println(key + "," + value);
		});
	}

}
