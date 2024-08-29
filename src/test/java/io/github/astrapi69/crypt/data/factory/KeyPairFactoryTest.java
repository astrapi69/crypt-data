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
package io.github.astrapi69.crypt.data.factory;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
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

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeySize;
import io.github.astrapi69.crypt.api.provider.SecurityProvider;
import io.github.astrapi69.crypt.data.algorithm.AlgorithmExtensions;
import io.github.astrapi69.crypt.data.extension.CsvReader;
import io.github.astrapi69.crypt.data.extension.LineAppender;
import io.github.astrapi69.crypt.data.key.KeySizeExtensions;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.crypt.data.model.KeyPairInfo;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.lang.thread.ThreadExtensions;
import lombok.extern.java.Log;

/**
 * The unit test class for the class {@link KeyPairFactory}
 */
@Log
public class KeyPairFactoryTest
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
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@Test
	@Disabled
	public void testWithAllExistingAlgorithms() throws IOException
	{
		final List<KeyPairEntry> validKeyPairEntries = ListFactory.newArrayList();
		List<KeyPairEntry> completedKeypairEntries;
		List<KeyPairEntry> testKeypairEntries;
		List<KeyPairEntry> invalidKeyPairEntries;

		File validCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new_valid_key_pair_algorithms.csv");
		File testKeypairAlgorithmsCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"test_key_pair_algorithms.csv");
		File invalidCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"invalid_key_pair_algorithms.csv");

		if (!invalidCsvFile.exists())
		{
			invalidKeyPairEntries = ListFactory.newArrayList();
			LineAppender.appendLines(invalidCsvFile, "algorithm,keysize");
		}
		else
		{
			invalidKeyPairEntries = CsvReader.readKeyPairEntriesFromCsv(invalidCsvFile);
		}

		if (!validCsvFile.exists())
		{
			completedKeypairEntries = ListFactory.newArrayList();
			LineAppender.appendLines(validCsvFile, "algorithm,keysize");
		}
		else
		{
			completedKeypairEntries = CsvReader.readKeyPairEntriesFromCsv(validCsvFile);
		}

		if (!testKeypairAlgorithmsCsvFile.exists())
		{
			testKeypairEntries = null;
			LineAppender.appendLines(testKeypairAlgorithmsCsvFile, "algorithm,keysize");
		}
		else
		{
			testKeypairEntries = CsvReader.readKeyPairEntriesFromCsv(testKeypairAlgorithmsCsvFile);
		}

		// Use the new method to process the key pair entries
		processKeyPairEntries(testKeypairEntries, validKeyPairEntries, invalidKeyPairEntries,
			completedKeypairEntries, validCsvFile, invalidCsvFile, 60);

		validKeyPairEntries.forEach(keyPairEntry -> {
			try
			{
				LineAppender.appendLines(validCsvFile,
					keyPairEntry.getAlgorithm() + "," + keyPairEntry.getKeySize());
			}
			catch (IOException e)
			{
				log.log(Level.WARNING, "Entry '" + keyPairEntry.getAlgorithm() + ","
					+ keyPairEntry.getKeySize() + "' throws IOException", e);
			}
		});
	}

	public void processKeyPairEntries(List<KeyPairEntry> testKeypairEntries,
		List<KeyPairEntry> validKeyPairEntries, List<KeyPairEntry> invalidKeyPairEntries,
		List<KeyPairEntry> completedKeypairEntries, File validCsvFile, File invalidCsvFile,
		long timeoutSeconds)
	{
		// Create a thread pool from the available processor cores
		int cores = Runtime.getRuntime().availableProcessors();
		ExecutorService executorService = Executors.newFixedThreadPool(cores);

		testKeypairEntries.forEach(keyPairEntry -> {
			Runnable task = () -> {
				boolean containsInValidAlgorithm = validKeyPairEntries.contains(keyPairEntry);
				boolean containsInProcessedAlgorithm = completedKeypairEntries
					.contains(keyPairEntry);
				boolean containsInInvalidAlgorithm = invalidKeyPairEntries.contains(keyPairEntry);
				String algorithm = keyPairEntry.getAlgorithm();
				Integer keySize = keyPairEntry.getKeySize();

				if (!containsInValidAlgorithm && !containsInProcessedAlgorithm
					&& !containsInInvalidAlgorithm)
				{
					try
					{
						System.out.println(
							"Start task with algorithm: " + algorithm + " , keysize: " + keySize);
						KeyPair keyPair = KeyPairFactory.newKeyPair(algorithm, keySize);
						PrivateKey privateKey = keyPair.getPrivate();
						PublicKey publicKey = keyPair.getPublic();
						validKeyPairEntries.add(keyPairEntry);

						LineAppender.appendLines(validCsvFile, algorithm + "," + keySize);
						System.out.println("Task " + "algorithm: " + algorithm + " , keysize: "
							+ keySize + " completed");
					}
					catch (NoSuchAlgorithmException | NoSuchProviderException e)
					{
						invalidKeyPairEntries.add(keyPairEntry);
						try
						{
							LineAppender.appendLines(invalidCsvFile, algorithm + "," + keySize);
						}
						catch (IOException ex)
						{
							log.log(Level.WARNING, "Algorithm did not save to file "
								+ invalidCsvFile.getName() + " : " + keyPairEntry.getAlgorithm(),
								ex);
						}
						log.log(Level.WARNING, "Algorithm throws: " + keyPairEntry.getAlgorithm(),
							e);
					}
					catch (IOException e)
					{
						log.log(Level.WARNING, "Algorithm did not save to file "
							+ validCsvFile.getName() + " : " + keyPairEntry.getAlgorithm(), e);
					}
				}
				else
				{
					System.out
						.println("algorithm: " + algorithm + " , keysize: " + keySize + " exists");
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
					invalidKeyPairEntries.add(keyPairEntry);
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
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
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
			invalidKeyPairEntries = CsvReader.readKeyPairEntriesFromCsv(invalidCsvFile);
		}

		if (!validCsvFile.exists())
		{
			validKeyPairEntries = null;
			LineAppender.appendLines(validCsvFile, "algorithm,keysize");
		}
		else
		{
			validKeyPairEntries = CsvReader.readKeyPairEntriesFromCsv(validCsvFile);
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

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(Algorithm, KeySize)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@Test
	public void testNewKeyPairAlgorithmKeySize()
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyPair actual;

		actual = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.DIFFIE_HELLMAN,
			KeySize.KEYSIZE_2048);
		assertNotNull(actual);

		actual = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.DSA, KeySize.KEYSIZE_2048);
		assertNotNull(actual);

		actual = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.EC, KeySize.KEYSIZE_2048);
		assertNotNull(actual);

		actual = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		assertNotNull(actual);

		actual = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSASSA_PSS,
			KeySize.KEYSIZE_2048);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(File, File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@Test
	public void testNewKeyPairFileFile() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		File derDir;
		File publicKeyDerFile;
		File privateKeyDerFile;
		KeyPair actual;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publicKeyDerFile = new File(derDir, "public.der");
		privateKeyDerFile = new File(derDir, "private.der");

		actual = KeyPairFactory.newKeyPair(publicKeyDerFile, privateKeyDerFile);
		assertNotNull(actual);
	}


	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(PublicKey, PrivateKey)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testProtectPrivateKeyWithPassword() throws Exception
	{

		File publicKeyDerDir;
		File publicKeyDerFile;
		File privateKeyDerFile;
		PrivateKey privateKey;
		PublicKey publicKey;
		KeyPair keyPair;

		publicKeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publicKeyDerFile = new File(publicKeyDerDir, "public.der");
		privateKeyDerFile = new File(publicKeyDerDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privateKeyDerFile);

		publicKey = PublicKeyReader.readPublicKey(publicKeyDerFile);

		keyPair = KeyPairFactory.newKeyPair(publicKey, privateKey);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyPairFactory.class);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(ECNamedCurveParameterSpec, String, String)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testNewKeyPairWithECNamedCurveParameterSpec()
		throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException
	{
		// the name of the curve
		KeyPair keyPair;
		String eCurveNameAlgorithm;
		final String algorithm;
		final String provider;
		ECNamedCurveParameterSpec parameterSpec;

		algorithm = "ECDH";
		provider = SecurityProvider.BC.name();
		eCurveNameAlgorithm = "brainpoolp256r1";

		parameterSpec = ECNamedCurveTable.getParameterSpec(eCurveNameAlgorithm);

		keyPair = KeyPairFactory.newKeyPair(parameterSpec, algorithm, provider);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(ECNamedCurveParameterSpec, String, String)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testNewKeyPairWithECNamedCurveParameterSpecAsString()
		throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException
	{

		KeyPair keyPair;
		// the name of the curve
		String eCurveNameAlgorithm;
		final String algorithm;
		final String provider;


		eCurveNameAlgorithm = "brainpoolp256r1";
		algorithm = "ECDH";
		provider = SecurityProvider.BC.name();

		keyPair = KeyPairFactory.newKeyPair(eCurveNameAlgorithm, algorithm, provider);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(String)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@Test
	public void testNewKeyPairWithDefaultKeySize()
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyPair keyPair;

		keyPair = KeyPairFactory.newKeyPair("RSA");
		assertNotNull(keyPair);

		keyPair = KeyPairFactory.newKeyPair("DSA");
		assertNotNull(keyPair);

		keyPair = KeyPairFactory.newKeyPair("EC");
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(Algorithm)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@Test
	public void testNewKeyPairAlgorithm() throws NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyPair keyPair;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA);
		assertNotNull(keyPair);

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.DSA);
		assertNotNull(keyPair);

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.EC);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(PrivateKey)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 */
	@Test
	public void testNewKeyPairPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException,
		IOException, NoSuchProviderException
	{
		File derDir;
		File privateKeyDerFile;
		PrivateKey privateKey;
		KeyPair keyPair;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privateKeyDerFile);

		keyPair = KeyPairFactory.newKeyPair(privateKey);
		assertNotNull(keyPair);
	}

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(KeyPairInfo)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails
	 */
	@Test
	public void testNewKeyPairKeyPairInfo()
		throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		KeyPairInfo keyPairInfo;
		KeyPair keyPair;

		keyPairInfo = KeyPairInfo.builder().algorithm("ECDH")
			.eCNamedCurveParameterSpecName("brainpoolp256r1").provider(SecurityProvider.BC.name())
			.build();

		keyPair = KeyPairFactory.newKeyPair(keyPairInfo);
		assertNotNull(keyPair);

		keyPairInfo = KeyPairInfo.builder().algorithm("ECDH")
			.eCNamedCurveParameterSpecName("brainpoolp256r1").build();

		keyPair = KeyPairFactory.newKeyPair(keyPairInfo);
		assertNotNull(keyPair);

		keyPairInfo = KeyPairInfo.builder().algorithm("RSA").keySize(2048).build();

		keyPair = KeyPairFactory.newKeyPair(keyPairInfo);
		assertNotNull(keyPair);
	}
}
