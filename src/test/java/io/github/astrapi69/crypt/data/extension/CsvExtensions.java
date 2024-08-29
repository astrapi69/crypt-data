package io.github.astrapi69.crypt.data.extension;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import io.github.astrapi69.crypt.data.factory.KeyPairEntry;

import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

public class CsvExtensions
{

	/**
	 * Reads a CSV file, sorts the data by algorithm and keysize in ascending order,
	 * and writes the sorted data back to the CSV file.
	 *
	 * @param csvFilePath the path to the CSV file to be sorted
	 * @throws IOException if an I/O error occurs
	 */
	public static void sortCsvByAlgorithmAndKeysize(Path csvFilePath) throws IOException {
		// Read the CSV file lines
		List<String> lines = Files.readAllLines(csvFilePath);

		// Extract header
		String header = lines.get(0);

		// Sort the remaining lines based on the algorithm and keysize
		List<String> sortedLines = lines.stream()
				.skip(1) // Skip the header
				.map(line -> line.split(",")) // Split the line into columns
				.sorted(Comparator.comparing((String[] columns) -> columns[0]) // First sort by algorithm
						.thenComparingInt(columns -> Integer.parseInt(columns[1]))) // Then sort by keysize
				.map(columns -> String.join(",", columns)) // Join the columns back into a line
				.collect(Collectors.toList());

		// Add the header back to the sorted lines
		sortedLines.add(0, header);

		// Write the sorted lines back to the file
		Files.write(csvFilePath, sortedLines);
	}

	public static List<KeyPairEntry> readKeyPairEntriesFromCsv(File csvFile) throws IOException
	{
		List<KeyPairEntry> keyPairEntries = new ArrayList<>();

		CSVFormat csvFormat = CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true)
			.build();

		try (FileReader reader = new FileReader(csvFile);
			CSVParser csvParser = new CSVParser(reader, csvFormat))
		{
			for (CSVRecord csvRecord : csvParser)
			{
				String algorithm = csvRecord.get("algorithm");
				String keySizeString = csvRecord.get("keysize");

				Integer keySize = keySizeString.isEmpty() ? null : Integer.valueOf(keySizeString);

				KeyPairEntry entry = KeyPairEntry.builder().algorithm(algorithm).keySize(keySize)
					.build();

				keyPairEntries.add(entry);
			}
		}
		return keyPairEntries;
	}


}
