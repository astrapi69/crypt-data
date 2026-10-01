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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.function.Supplier;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapisixtynine.csv.CsvExtensions;

/**
 * The unit test class for the class {@link TestCsvExtensions}
 */
class CsvExtensionsTest
{

	/**
	 * Where this test writes. The sorting methods sort a file in place, and these tests used to
	 * hand them the committed fixtures, so every run rewrote tracked files in the working tree
	 * (#54). They now sort a copy here, which JUnit removes with the test's own directory.
	 */
	@TempDir
	Path temporaryDirectory;

	/**
	 * A copy of a committed, sorted fixture with its data rows in reverse order, so that sorting it
	 * has something to do and the result can be compared with the fixture itself
	 */
	private Path reversedCopyOf(final String fixtureName) throws IOException
	{
		List<String> lines = Files.readAllLines(fixture(fixtureName).toPath());
		List<String> reversed = new ArrayList<>(lines.subList(1, lines.size()));
		Collections.reverse(reversed);
		reversed.add(0, lines.get(0));
		Path copy = temporaryDirectory.resolve(fixtureName);
		Files.write(copy, reversed);
		return copy;
	}

	private static File fixture(final String fixtureName)
	{
		return new File(PathFinder.getSrcTestResourcesDir(), fixtureName);
	}

	/**
	 * Test method for {@link CsvExtensions#sortCsv(Path, Supplier)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	void sortCsvFileWithSupplier() throws IOException
	{
		Path csvFilePath = reversedCopyOf("invalid_key_pair_algorithms.csv");

		// Example usage with algorithm and keysize as sorting criteria
		Supplier<Comparator<String[]>> comparatorSupplier = () -> Comparator
			.comparing((String[] columns) -> columns[0]) // Sort by 'algorithm'
			.thenComparingInt(columns -> Integer.parseInt(columns[1])); // Then by 'keysize'

		CsvExtensions.sortCsv(csvFilePath, comparatorSupplier);

		assertEquals(Files.readAllLines(fixture("invalid_key_pair_algorithms.csv").toPath()),
			Files.readAllLines(csvFilePath));
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

		Path csvFilePath = reversedCopyOf("new_valid_key_pair_algorithms.csv");

		CsvExtensions.sortCsvByAlgorithmAndKeysize(csvFilePath);

		assertEquals(Files.readAllLines(fixture("new_valid_key_pair_algorithms.csv").toPath()),
			Files.readAllLines(csvFilePath));
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
		Path csvFilePath = reversedCopyOf(
			"valid_jdk_17_provider_bc_certificate_signature_algorithms.csv");
		CsvExtensions.sortCsvByKeypairAndSignatureAlgorithm(csvFilePath);
		csvFilePath = reversedCopyOf("invalid_certificate_signature_algorithms.csv");
		CsvExtensions.sortCsvByKeypairAndSignatureAlgorithm(csvFilePath);
		System.out.println("CSV file sorted successfully.");
	}
}