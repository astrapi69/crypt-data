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
package io.github.astrapi69.crypt.data.extension;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.function.Supplier;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapisixtynine.csv.CsvExtensions;

/**
 * The unit test class for the class {@link TestCsvExtensions}
 */
class CsvExtensionsTest
{

	/**
	 * Test method for {@link CsvExtensions#sortCsv(Path, Supplier)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	void sortCsvFileWithSupplier() throws IOException
	{
		File validCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"invalid_key_pair_algorithms.csv");
		// Example usage with a CSV file path
		Path csvFilePath = validCsvFile.toPath();

		// Example usage with algorithm and keysize as sorting criteria
		Supplier<Comparator<String[]>> comparatorSupplier = () -> Comparator
			.comparing((String[] columns) -> columns[0]) // Sort by 'algorithm'
			.thenComparingInt(columns -> Integer.parseInt(columns[1])); // Then by 'keysize'

		CsvExtensions.sortCsv(csvFilePath, comparatorSupplier);
	}

	/**
	 * Test method for {@link CsvExtensions#sortCsvByAlgorithmAndKeysize(Path)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	void sortCsvByAlgorithmAndKeysize() throws IOException
	{

		File validCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new_valid_key_pair_algorithms.csv");
		// Example usage with a CSV file path
		Path csvFilePath = validCsvFile.toPath();
		CsvExtensions.sortCsvByAlgorithmAndKeysize(csvFilePath);
	}

	/**
	 * Test method for {@link CsvExtensions#sortCsvByKeypairAndSignatureAlgorithm(Path)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	@Disabled
	void sortCsvByKeypairAndSignatureAlgorithm() throws IOException
	{
		File invalidCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"invalid_certificate_signature_algorithms.csv");
		File validCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"valid_jdk_17_provider_bc_certificate_signature_algorithms.csv");
		// Example usage with a CSV file path
		Path csvFilePath = validCsvFile.toPath();
		CsvExtensions.sortCsvByKeypairAndSignatureAlgorithm(csvFilePath);
		csvFilePath = invalidCsvFile.toPath();
		CsvExtensions.sortCsvByKeypairAndSignatureAlgorithm(csvFilePath);
		System.out.println("CSV file sorted successfully.");
	}
}