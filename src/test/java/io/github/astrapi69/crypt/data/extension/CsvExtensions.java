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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import io.github.astrapi69.crypt.data.processor.certificate.CertificateAlgorithmEntry;
import io.github.astrapi69.crypt.data.processor.keypair.KeyPairEntry;

/**
 * The {@code CsvExtensions} class provides utility methods to read data from CSV files, map the
 * data to objects, and generate maps of data from lists of objects. This class supports reading CSV
 * files using Apache Commons CSV and creating data structures like lists and maps from the parsed
 * CSV data
 */
public class CsvExtensions
{

	/**
	 * Sorts a CSV file by 'keypair-algorithm' and 'signature-algorithm', removes duplicates, and
	 * rewrites the sorted data back to the CSV file
	 *
	 * @param csvFilePath
	 *            the path to the CSV file to be sorted
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static void sortCsvByKeypairAndSignatureAlgorithm(Path csvFilePath) throws IOException
	{
		List<String> lines = Files.readAllLines(csvFilePath);
		String header = lines.get(0);

		Set<String> sortedUniqueLines = lines.stream().skip(1).map(line -> line.split(","))
			.sorted(Comparator.comparing((String[] columns) -> columns[0])
				.thenComparing(columns -> columns[1]))
			.map(columns -> String.join(",", columns))
			.collect(Collectors.toCollection(LinkedHashSet::new));

		sortedUniqueLines.add(header);
		Files.write(csvFilePath, sortedUniqueLines);
	}

	/**
	 * Reads a CSV file, sorts its data based on a supplied comparator, and writes the sorted data
	 * back to the file.
	 *
	 * @param csvFilePath
	 *            the path to the CSV file to be sorted
	 * @param comparatorSupplier
	 *            a supplier that provides a comparator for sorting the rows
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static void sortCsv(Path csvFilePath, Supplier<Comparator<String[]>> comparatorSupplier)
		throws IOException
	{
		List<String> lines = Files.readAllLines(csvFilePath);
		String header = lines.get(0);

		List<String> sortedLines = lines.stream().skip(1).map(line -> line.split(","))
			.sorted(comparatorSupplier.get()).map(columns -> String.join(",", columns))
			.collect(Collectors.toList());

		sortedLines.add(0, header);
		Files.write(csvFilePath, sortedLines);
	}

	/**
	 * Reads a CSV file, sorts its data by 'algorithm' and 'keysize' in ascending order, and writes
	 * the sorted data back to the file
	 *
	 * @param csvFilePath
	 *            the path to the CSV file to be sorted
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static void sortCsvByAlgorithmAndKeysize(Path csvFilePath) throws IOException
	{
		Supplier<Comparator<String[]>> comparatorSupplier = () -> Comparator
			.comparing((String[] columns) -> columns[0]) // Sort by 'algorithm'
			.thenComparingInt(columns -> Integer.parseInt(columns[1])); // Then by 'keysize'
		sortCsv(csvFilePath, comparatorSupplier);
	}

	/**
	 * Reads entries from a CSV input stream, processes each record using a provided mapper
	 * function, and returns a list of mapped entries
	 *
	 * @param <T>
	 *            the generic type of the returned entries
	 * @param csvInputStream
	 *            the input stream of the CSV file
	 * @param recordMapper
	 *            a function that maps each CSV record to an object of type T
	 * @return a list of mapped entries of type T
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static <T> List<T> readEntriesFromCsv(InputStream csvInputStream,
		Function<CSVRecord, T> recordMapper) throws IOException
	{
		List<T> entries = new ArrayList<>();

		CSVFormat csvFormat = CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true)
			.build();

		try (BufferedReader reader = new BufferedReader(new InputStreamReader(csvInputStream));
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

	/**
	 * Reads entries from a CSV file, processes each record using a provided mapper function, and
	 * returns a list of mapped entries
	 *
	 * @param <T>
	 *            the generic type of the returned entries
	 * @param csvFile
	 *            the CSV file to read from
	 * @param recordMapper
	 *            a function that maps each CSV record to an object of type T
	 * @return a list of mapped entries of type T
	 * @throws IOException
	 *             if an I/O error occurs
	 */
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

	/**
	 * Reads key-pair entries from a CSV file and returns a list of {@link KeyPairEntry}
	 *
	 * @param csvFile
	 *            the CSV file to read from
	 * @return a list of {@link KeyPairEntry}
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static List<KeyPairEntry> readKeyPairEntriesFromCsv(File csvFile) throws IOException
	{
		return readEntriesFromCsv(csvFile, csvRecord -> {
			String algorithm = csvRecord.get("algorithm");
			String keySizeString = csvRecord.get("keysize");
			Integer keySize = keySizeString.isEmpty() ? null : Integer.valueOf(keySizeString);

			return KeyPairEntry.builder().algorithm(algorithm).keySize(keySize).build();
		});
	}

	/**
	 * Reads certificate algorithm entries from a CSV file and returns a list of
	 * {@link CertificateAlgorithmEntry}
	 *
	 * @param csvFile
	 *            the CSV file to read from
	 * @return a list of {@link CertificateAlgorithmEntry}
	 * @throws IOException
	 *             if an I/O error occurs
	 */
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

	/**
	 * Reads certificate algorithm entries from a CSV input stream and returns a list of
	 * {@link CertificateAlgorithmEntry}
	 *
	 * @param csvFile
	 *            the input stream of the CSV file to read from
	 * @return a list of {@link CertificateAlgorithmEntry}
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static List<CertificateAlgorithmEntry> readCertificateAlgorithmEntryFromCsv(
		InputStream csvFile) throws IOException
	{
		return readEntriesFromCsv(csvFile, csvRecord -> {
			String algorithm = csvRecord.get("keypair-algorithm");
			String signatureAlgorithm = csvRecord.get("signature-algorithm");

			return CertificateAlgorithmEntry.builder().keyPairAlgorithm(algorithm)
				.signatureAlgorithm(signatureAlgorithm).build();
		});
	}
}
