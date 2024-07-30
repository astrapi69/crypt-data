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
	public static final String[] HEADERS = { "extensionId", "critical", "value" };

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
		CSVFormat csvFormat = CSVFormat.DEFAULT.builder().setHeader(HEADERS)
			.setSkipHeaderRecord(true).build();

		try (Reader reader = new FileReader(csvFilePath);
			CSVParser csvParser = new CSVParser(reader, csvFormat))
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
