package io.github.astrapi69.crypt.data.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;

import org.junit.jupiter.api.Test;

public class ExtensionInfoCSVReaderTest
{

	@Test
	void testReadExtensionInfoFromCSV() throws IOException
	{
		ExtensionInfo[] extensionInfos = ExtensionInfoCSVReader
			.readExtensionInfoFromCSV("src/test/resources/extension_info_data.csv");

		assertNotNull(extensionInfos);
		assertEquals(17, extensionInfos.length);

		ExtensionInfo firstExtension = extensionInfos[0];
		assertEquals("1.3.6.1.4.1.11129.2.4.2", firstExtension.getExtensionId());
		assertEquals(true, firstExtension.isCritical());
		assertEquals("testValue1", firstExtension.getValue());

		ExtensionInfo secondExtension = extensionInfos[1];
		assertEquals("1.2.840.113549.1.1.5", secondExtension.getExtensionId());
		assertEquals(false, secondExtension.isCritical());
		assertEquals("testValue2", secondExtension.getValue());

		// Add more assertions as needed
	}
}
