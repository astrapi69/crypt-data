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

import java.io.FileWriter;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Set;

/**
 * Utility class for creating a CSV file for parameterized JUnit 5 tests.
 */
public class CryptoServiceCsvGenerator
{

	/**
	 * Generates a CSV file with service names and their expected algorithms for parameterized JUnit
	 * 5 tests.
	 *
	 * @param filePath
	 *            the path of the CSV file to create
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static void generateCryptoServicesWithAlgorithmsCsvFile(String filePath)
		throws IOException
	{
		// Retrieve all providers
		Provider[] providers = Security.getProviders();
		// Retrieve all service names from the providers
		Set<String> serviceNames = AlgorithmExtensions.getAllServiceNames(providers);

		try (FileWriter writer = new FileWriter(filePath))
		{
			// Write header
			writer.write("serviceName;expectedAlgorithms\n");

			// Iterate through all service names
			for (String serviceName : serviceNames)
			{
				// Get algorithms for the service name
				Set<String> algorithms = AlgorithmExtensions.getAlgorithms(serviceName);
				// Join algorithms into a comma-separated string
				String algorithmsStr = String.join(",", algorithms);
				// Write service name and algorithms to the CSV file
				writer.write(serviceName + ";" + algorithmsStr + "\n");
			}
		}
	}

	public static void main(String[] args)
	{
		try
		{
			// Generate the CSV file
			generateCryptoServicesWithAlgorithmsCsvFile("crypto_services.csv");
			System.out.println("CSV file generated successfully.");
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
}
