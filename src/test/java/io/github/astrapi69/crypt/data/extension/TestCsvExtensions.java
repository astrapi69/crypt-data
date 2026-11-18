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
import java.io.Reader;
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
 * The {@code TestCsvExtensions} class provides the utility methods the tests use to read data from
 * CSV files, map the data to objects, and sort the fixture files. It reads CSV files with Apache
 * Commons CSV; the reading and sorting helpers are the ones of csv-worker 1.0, which the tests no
 * longer depend on
 */
public class TestCsvExtensions
{

	/**
	 * Reads the records of a CSV file with a header line and maps each one to an entry
	 *
	 * @param <T>
	 *            the type of the entries
	 * @param csvFile
	 *            the CSV file to read from
	 * @param recordMapper
	 *            the function that maps a record to an entry
	 * @return the entries in the order of the file
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static <T> List<T> readEntriesFromCsv(final File csvFile,
		final Function<CSVRecord, T> recordMapper) throws IOException
	{
		try (Reader reader = new FileReader(csvFile))
		{
			return readEntries(reader, recordMapper);
		}
	}

	/**
	 * Reads the records of a CSV input stream with a header line and maps each one to an entry
	 *
	 * @param <T>
	 *            the type of the entries
	 * @param csvInputStream
	 *            the input stream to read from
	 * @param recordMapper
	 *            the function that maps a record to an entry
	 * @return the entries in the order of the stream
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static <T> List<T> readEntriesFromCsv(final InputStream csvInputStream,
		final Function<CSVRecord, T> recordMapper) throws IOException
	{
		try (Reader reader = new BufferedReader(new InputStreamReader(csvInputStream)))
		{
			return readEntries(reader, recordMapper);
		}
	}

	private static <T> List<T> readEntries(final Reader reader,
		final Function<CSVRecord, T> recordMapper) throws IOException
	{
		List<T> entries = new ArrayList<>();
		CSVFormat csvFormat = CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true)
			.build();
		try (CSVParser csvParser = new CSVParser(reader, csvFormat))
		{
			for (CSVRecord csvRecord : csvParser)
			{
				entries.add(recordMapper.apply(csvRecord));
			}
		}
		return entries;
	}

	/**
	 * Sorts the lines of a CSV file below its header line with the given comparator over the
	 * columns of each line, and writes them back
	 *
	 * @param csvFilePath
	 *            the path of the CSV file
	 * @param comparatorSupplier
	 *            the supplier of the comparator over the columns of a line
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static void sortCsv(final Path csvFilePath,
		final Supplier<Comparator<String[]>> comparatorSupplier) throws IOException
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
	 * Sorts the lines of a CSV file below its header line by the first column, the algorithm, and
	 * then by the second column, the key size, as a number
	 *
	 * @param csvFilePath
	 *            the path of the CSV file
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static void sortCsvByAlgorithmAndKeysize(final Path csvFilePath) throws IOException
	{
		sortCsv(csvFilePath, () -> Comparator.comparing((String[] columns) -> columns[0])
			.thenComparingInt(columns -> Integer.parseInt(columns[1])));
	}

	/**
	 * Sorts the lines of a CSV file by its first and then its second column and drops duplicate
	 * lines; as in csv-worker 1.0, the header line is appended after the sorted lines unless it is
	 * one of them already
	 *
	 * @param csvFilePath
	 *            the path of the CSV file
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static void sortCsvByKeypairAndSignatureAlgorithm(final Path csvFilePath)
		throws IOException
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
