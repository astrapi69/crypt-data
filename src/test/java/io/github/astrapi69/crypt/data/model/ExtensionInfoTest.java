package io.github.astrapi69.crypt.data.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.FileReader;
import java.io.IOException;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.model.ExtensionInfo;

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
public class ExtensionInfoTest
{

	/**
	 * Test method to verify the conversion from {@link ExtensionInfo} to {@link Extension}.
	 * 
	 * @param extensionId
	 *            The identifier of the extension.
	 * @param critical
	 *            Indicates whether the extension is critical.
	 * @param value
	 *            The value of the extension.
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/extension_info_data.csv", numLinesToSkip = 1)
	void testToExtension(String extensionId, boolean critical, String value)
	{
		ExtensionInfo extensionInfo = ExtensionInfo.builder().extensionId(extensionId)
			.critical(critical).value(value).build();

		Extension extension = ExtensionInfo.toExtension(extensionInfo);

		assertEquals(extensionId, extension.getExtnId().getId());
		assertEquals(critical, extension.isCritical());
		assertEquals(value, new String(extension.getExtnValue().getOctets()));
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
}
