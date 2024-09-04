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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.crypt.data.extension.LineAppender;
import io.github.astrapi69.crypt.data.key.KeySizeInitializer;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;
import lombok.extern.java.Log;

/**
 * The class {@code CertificateVerifierTest} provides unit tests for the methods of the
 * {@code CertificateVerifier} class
 */
@Log
class SignatureAlgorithmResolverTest
{

	/**
	 * Sets up the test environment by adding the BouncyCastle security provider
	 */
	@BeforeEach
	public void setUp()
	{
		// Add BouncyCastle as a security provider for the tests
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Test method for
	 * {@link SignatureAlgorithmResolver#getSupportedSignatureAlgorithms(String, Class, KeySizeInitializer, int, int, int)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             if the algorithm is not available in the environment
	 * @throws NoSuchProviderException
	 *             if the provider is not available in the environment
	 * @throws InvocationTargetException
	 *             if an exception occurs during the method invocation
	 * @throws NoSuchMethodException
	 *             if a particular method cannot be found
	 * @throws IllegalAccessException
	 *             if access to the method is denied
	 */
	@Test
	@Disabled("only for local unit testing")
	void getSupportedSignatureAlgorithms() throws NoSuchAlgorithmException, NoSuchProviderException,
		InvocationTargetException, NoSuchMethodException, IllegalAccessException, IOException
	{
		Map<String, Set<String>> supportedSignatureAlgorithms = SignatureAlgorithmResolver
			.getSupportedSignatureAlgorithms("KeyPairGenerator", KeyPairGenerator.class,
				KeyPairGenerator::initialize, 255, 2048, 1);

		// Assert that the result is not null
		assertNotNull(supportedSignatureAlgorithms);
		File validSignatureAlgorithmsCsvFile = FileFactory.newFile(
			PathFinder.getSrcTestResourcesDir(),
			"new_valid_jdk_17_provider_bc_certificate_signature_algorithms.csv");

		writeToCsv(validSignatureAlgorithmsCsvFile, supportedSignatureAlgorithms);
	}

	private static void writeToCsv(File validSignatureAlgorithmsCsvFile,
		Map<String, Set<String>> supportedSignatureAlgorithms)
	{
		try
		{
			LineAppender.appendLines(validSignatureAlgorithmsCsvFile,
				"keypair-algorithm" + "," + "signature-algorithm");
		}
		catch (IOException e)
		{
			log.log(Level.WARNING, "IOException while appending entry to file: "
				+ validSignatureAlgorithmsCsvFile.getName(), e);
		}
		supportedSignatureAlgorithms.forEach((key, value) -> {
			List<String> signatureAlgorithms = ListFactory.newSortedUniqueList(value);
			signatureAlgorithms.forEach(signatureAlgorithm -> {
				try
				{
					LineAppender.appendLines(validSignatureAlgorithmsCsvFile,
						key + "," + signatureAlgorithm);
				}
				catch (IOException e)
				{
					log.log(Level.WARNING, "IOException while appending entry to file: "
						+ validSignatureAlgorithmsCsvFile.getName(), e);
				}
			});
		});
	}

	/**
	 * Test method for {@link SignatureAlgorithmResolverTest#loadSignatureAlgorithmsFromCSV(File)}
	 *
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	@Test
	@Disabled("only used for compare loaded signature algorithms")
	public void testLoadCsvFile() throws IOException
	{
		File validSignatureAlgorithmsCsvFile = FileFactory.newFile(
			PathFinder.getSrcTestResourcesDir(),
			"valid_jdk_17_provider_bc_certificate_signature_algorithms.csv");
		Map<String, Set<String>> supportedSignatureAlgorithms = loadSignatureAlgorithmsFromCSV(
			validSignatureAlgorithmsCsvFile);
		// Assert that the result is not null
		assertNotNull(supportedSignatureAlgorithms);
	}

	/**
	 * Loads signature algorithms from the specified CSV file
	 *
	 * @param csvFilePath
	 *            the path to the CSV file
	 * @return a map where the key is the key pair algorithm and the value is a set of signature
	 *         algorithms associated with the key pair algorithm
	 * @throws IOException
	 *             if an I/O error occurs while reading the file
	 */
	public static Map<String, Set<String>> loadSignatureAlgorithmsFromCSV(File csvFilePath)
		throws IOException
	{
		Map<String, Set<String>> supportedSignatureAlgorithmsMap = new HashMap<>();

		try (BufferedReader br = new BufferedReader(new FileReader(csvFilePath)))
		{
			String line;
			while ((line = br.readLine()) != null)
			{
				// Assume CSV format is "keyPairAlgorithm,signatureAlgorithm"
				String[] values = line.split(",");
				if (values.length != 2)
				{
					continue; // Skip any improperly formatted lines
				}

				String keyPairAlgorithm = values[0].trim();
				String signatureAlgorithm = values[1].trim();
				if (keyPairAlgorithm.equalsIgnoreCase("keypair-algorithm"))
				{
					continue;
				}
				// Add to the map
				supportedSignatureAlgorithmsMap
					.computeIfAbsent(keyPairAlgorithm, k -> new HashSet<>())
					.add(signatureAlgorithm);
			}
		}

		return supportedSignatureAlgorithmsMap;
	}

}
