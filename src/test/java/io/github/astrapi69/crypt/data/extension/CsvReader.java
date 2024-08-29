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

public class CsvReader
{


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
