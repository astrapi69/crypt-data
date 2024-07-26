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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Test class for {@link ExtensionInfo} using JUnit 5 with parameterized tests.
 * <p>
 * This class tests the conversion methods between {@link ExtensionInfo} and {@link Extension} using
 * various valid OID examples.
 * </p>
 * <h3>Valid OID Examples</h3>
 * <ul>
 * <li>1.3.6.1.4.1.11129.2.4.2: Google Certificate Transparency (CT) log.</li>
 * <li>1.2.840.113549.1.1.5: SHA-1 with RSA encryption (RSA signature).</li>
 * <li>2.5.4.3: Common Name (CN) attribute type in X.500 directories.</li>
 * <li>2.16.840.1.113730.1.1: Netscape Certificate Type.</li>
 * <li>1.2.840.10045.4.3.2: ECDSA with SHA-256.</li>
 * <li>1.3.6.1.5.5.7.3.1: TLS Web Server Authentication.</li>
 * <li>1.3.6.1.5.5.7.3.2: TLS Web Client Authentication.</li>
 * </ul>
 */
@DisplayName("Parameterized tests for ExtensionInfo")
public class ExtensionInfoParameterizedTest
{

	/**
	 * Parameterized test for {@link ExtensionInfo#fromExtension(Extension)} using CSV file
	 *
	 * @param extensionId
	 *            the identifier of the extension
	 * @param critical
	 *            indicates whether the extension is critical
	 * @param value
	 *            the value of the extension
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/extension_info_data.csv", numLinesToSkip = 1)
	void testFromExtensionParameterized(String extensionId, boolean critical, String value)
	{
		Extension extension = new Extension(new ASN1ObjectIdentifier(extensionId), critical,
			new DEROctetString(value.getBytes()));
		ExtensionInfo result = ExtensionInfo.fromExtension(extension);
		assertNotNull(result);
		assertEquals(extensionId, result.getExtensionId());
		assertEquals(critical, result.isCritical());
		assertEquals(value, result.getValue());
	}

	/**
	 * Test method to verify the conversion from {@link Extension} to {@link ExtensionInfo}.
	 *
	 * @param extensionId
	 *            The identifier of the extension.
	 * @param critical
	 *            Indicates whether the extension is critical.
	 * @param value
	 *            The value of the extension.
	 */
	@ParameterizedTest
	@MethodSource("provideExtensionInfoArguments")
	void testFromExtension(String extensionId, boolean critical, String value)
	{
		ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(extensionId);
		byte[] extensionValue = value.getBytes();
		ASN1OctetString octetString = new DEROctetString(extensionValue);
		Extension extension = new Extension(oid, critical, octetString);

		ExtensionInfo extensionInfo = ExtensionInfo.fromExtension(extension);

		assertEquals(extensionId, extensionInfo.getExtensionId());
		assertEquals(critical, extensionInfo.isCritical());
		assertEquals(value, extensionInfo.getValue());
	}

	/**
	 * Provide a stream of arguments for parameterized tests.
	 *
	 * @return A stream of arguments.
	 */
	private static Stream<Arguments> provideExtensionInfoArguments()
	{
		// Provide test data here, if needed
		return Stream.of(Arguments.of("1.2.3.4", true, "testValue1"),
			Arguments.of("1.2.3.5", false, "testValue2"));
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
