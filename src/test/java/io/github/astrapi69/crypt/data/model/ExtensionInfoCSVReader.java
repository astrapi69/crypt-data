package io.github.astrapi69.crypt.data.model;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

/**
 * The type Extension info csv reader.
 */
public class ExtensionInfoCSVReader
{

	/**
	 * Reads the test data from CSV file and converts it to an array of {@link ExtensionInfo}
	 * objects
	 *
	 * @return an array of {@link ExtensionInfo} objects
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static ExtensionInfo[] readExtensionInfoFromCSV() throws IOException
	{
		return ExtensionInfoCSVReader
			.readExtensionInfoFromCSV("src/test/resources/extension_info_data.csv");
	}

	/**
	 * Reads a CSV file and converts it to an array of {@link ExtensionInfo} objects
	 *
	 * @param csvFilePath
	 *            the path to the CSV file
	 * @return an array of {@link ExtensionInfo} objects
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static ExtensionInfo[] readExtensionInfoFromCSV(String csvFilePath) throws IOException
	{
		try (Reader reader = new FileReader(csvFilePath);
			CSVParser csvParser = new CSVParser(reader,
				CSVFormat.DEFAULT.withFirstRecordAsHeader().withIgnoreHeaderCase().withTrim()))
		{

			List<ExtensionInfo> extensionInfos = new ArrayList<>();
			for (CSVRecord csvRecord : csvParser)
			{
				String extensionId = csvRecord.get("extensionId");
				boolean critical = Boolean.parseBoolean(csvRecord.get("critical"));
				String value = csvRecord.get("value");

				ExtensionInfo extensionInfo = ExtensionInfo.builder().extensionId(extensionId)
					.critical(critical).value(value).build();
				extensionInfos.add(extensionInfo);
			}

			return extensionInfos.toArray(new ExtensionInfo[0]);
		}
	}

}
