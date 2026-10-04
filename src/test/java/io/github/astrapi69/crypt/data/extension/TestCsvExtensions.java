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
import java.io.InputStream;
import java.util.List;

import io.github.astrapi69.crypt.data.processor.certificate.CertificateAlgorithmEntry;
import io.github.astrapi69.crypt.data.processor.keypair.KeyPairEntry;
import io.github.astrapisixtynine.csv.CsvExtensions;


/**
 * The {@code CsvExtensions} class provides utility methods to read data from CSV files, map the
 * data to objects, and generate maps of data from lists of objects. This class supports reading CSV
 * files using Apache Commons CSV and creating data structures like lists and maps from the parsed
 * CSV data
 */
public class TestCsvExtensions
{

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
		return CsvExtensions.readEntriesFromCsv(csvFile, csvRecord -> {
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
		return CsvExtensions.readEntriesFromCsv(csvFile, csvRecord -> {
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
		return CsvExtensions.readEntriesFromCsv(csvFile, csvRecord -> {
			String algorithm = csvRecord.get("keypair-algorithm");
			String signatureAlgorithm = csvRecord.get("signature-algorithm");

			return CertificateAlgorithmEntry.builder().keyPairAlgorithm(algorithm)
				.signatureAlgorithm(signatureAlgorithm).build();
		});
	}
}
