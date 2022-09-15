package io.github.astrapi69.crypt.data.certificate;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ExtensionInfoTest
{

	@Test
	public void newExtensionTest() throws IOException
	{
		ExtensionInfo actual;
		ExtensionInfo expected;
		DEROctetString value = new DEROctetString(
			new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment).toASN1Primitive()
				.getEncoded());
		actual = ExtensionInfo.builder().extensionId(Extension.keyUsage).critical(true).value(value)
			.build();

		Extension extension = ExtensionInfo.toExtension(actual);

		expected = ExtensionInfo.toExtensionInfo(extension);
		assertEquals(actual, expected);
	}
}
