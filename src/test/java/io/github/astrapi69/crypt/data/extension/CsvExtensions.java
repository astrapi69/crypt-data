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
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import io.github.astrapi69.crypt.data.processor.certificate.CertificateAlgorithmEntry;
import io.github.astrapi69.crypt.data.processor.keypair.KeyPairEntry;

public class CsvExtensions
{

	/**
	 * Sorts a CSV file by keypair-algorithm and signature-algorithm and removes duplicates.
	 *
	 * @param csvFilePath
	 *            the path to the CSV file to be sorted
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static void sortCsvByKeypairAndSignatureAlgorithm(Path csvFilePath) throws IOException
	{
		// Read the CSV file lines
		List<String> lines = Files.readAllLines(csvFilePath);

		// Extract header
		String header = lines.get(0);

		// Sort the remaining lines based on keypair-algorithm and signature-algorithm,
		// and remove duplicates by using a LinkedHashSet
		Set<String> sortedUniqueLines = lines.stream().skip(1) // Skip the header
			.map(line -> line.split(",")) // Split the line into columns
			.sorted(Comparator.comparing((String[] columns) -> columns[0]) // First sort by
																			// keypair-algorithm
				.thenComparing(columns -> columns[1])) // Then sort by signature-algorithm
			.map(columns -> String.join(",", columns)) // Join the columns back into a line
			.collect(Collectors.toCollection(LinkedHashSet::new)); // Remove duplicates and preserve
																	// order

		// Add the header back to the sorted unique lines
		sortedUniqueLines.add(header);

		// Write the sorted unique lines back to the file
		Files.write(csvFilePath, sortedUniqueLines);
	}

	/**
	 * Reads a CSV file, sorts the data by algorithm and keysize in ascending order, and writes the
	 * sorted data back to the CSV file.
	 *
	 * @param csvFilePath
	 *            the path to the CSV file to be sorted
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static void sortCsvByAlgorithmAndKeysize(Path csvFilePath) throws IOException
	{
		// Read the CSV file lines
		List<String> lines = Files.readAllLines(csvFilePath);

		// Extract header
		String header = lines.get(0);

		// Sort the remaining lines based on the algorithm and keysize
		List<String> sortedLines = lines.stream().skip(1) // Skip the header
			.map(line -> line.split(",")) // Split the line into columns
			.sorted(Comparator.comparing((String[] columns) -> columns[0]) // First sort by
																			// algorithm
				.thenComparingInt(columns -> Integer.parseInt(columns[1]))) // Then sort by keysize
			.map(columns -> String.join(",", columns)) // Join the columns back into a line
			.collect(Collectors.toList());

		// Add the header back to the sorted lines
		sortedLines.add(0, header);

		// Write the sorted lines back to the file
		Files.write(csvFilePath, sortedLines);
	}

	public static <T> List<T> readEntriesFromCsv(File csvFile, Function<CSVRecord, T> recordMapper)
		throws IOException
	{
		List<T> entries = new ArrayList<>();

		CSVFormat csvFormat = CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true)
			.build();

		try (FileReader reader = new FileReader(csvFile);
			CSVParser csvParser = new CSVParser(reader, csvFormat))
		{
			for (CSVRecord csvRecord : csvParser)
			{
				T entry = recordMapper.apply(csvRecord);
				entries.add(entry);
			}
		}
		return entries;
	}

	public static List<KeyPairEntry> readKeyPairEntriesFromCsv(File csvFile) throws IOException
	{
		return readEntriesFromCsv(csvFile, csvRecord -> {
			String algorithm = csvRecord.get("algorithm");
			String keySizeString = csvRecord.get("keysize");
			Integer keySize = keySizeString.isEmpty() ? null : Integer.valueOf(keySizeString);

			return KeyPairEntry.builder().algorithm(algorithm).keySize(keySize).build();
		});
	}

	public static List<CertificateAlgorithmEntry> readCertificateAlgorithmEntryFromCsv(File csvFile)
		throws IOException
	{
		return readEntriesFromCsv(csvFile, csvRecord -> {
			String algorithm = csvRecord.get("keypair-algorithm");
			String signatureAlgorithm = csvRecord.get("signature-algorithm");

			return CertificateAlgorithmEntry.builder().keyPairAlgorithm(algorithm)
				.signatureAlgorithm(signatureAlgorithm).build();
		});
	}
}
