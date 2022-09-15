package io.github.astrapi69.crypt.data.certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

public class ExtensionInfoTest
{

	@Test
	public void newExtensionTest() throws IOException, NoSuchAlgorithmException
	{
		ExtensionInfo actual;
		ExtensionInfo expected;
		DEROctetString value;
		Extension extension;
		// new test extension...
		value = new DEROctetString(
			new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment).toASN1Primitive()
				.getEncoded());
		actual = ExtensionInfo.builder().extensionId(Extension.keyUsage).critical(true).value(value)
			.build();

		extension = ExtensionInfo.toExtension(actual);

		expected = ExtensionInfo.toExtensionInfo(extension);
		assertEquals(actual, expected);
		// new test extension...
		BasicConstraints basicConstraints = new BasicConstraints(false);
		value = new DEROctetString(basicConstraints.toASN1Primitive().getEncoded());
		actual = ExtensionInfo.builder().extensionId(Extension.basicConstraints).critical(true)
			.value(value).build();

		extension = ExtensionInfo.toExtension(actual);

		expected = ExtensionInfo.toExtensionInfo(extension);
		assertEquals(actual, expected);
		// new test extension...
		value = new DEROctetString(
			new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).toASN1Primitive().getEncoded());
		actual = ExtensionInfo.builder().extensionId(Extension.extendedKeyUsage).critical(true)
			.value(value).build();

		extension = ExtensionInfo.toExtension(actual);

		expected = ExtensionInfo.toExtensionInfo(extension);
		assertEquals(actual, expected);
		// new test extension...
		value = new DEROctetString(
			new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test"))
				.toASN1Primitive().getEncoded());
		actual = ExtensionInfo.builder().extensionId(Extension.subjectAlternativeName)
			.critical(false).value(value).build();

		extension = ExtensionInfo.toExtension(actual);

		expected = ExtensionInfo.toExtensionInfo(extension);
		assertEquals(actual, expected);
		////// create or get certificate and public key for create extensions...
		// JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		// final Extension authorityKeyIdentifier = new Extension(Extension.authorityKeyIdentifier,
		// false,
		// extensionUtils.createAuthorityKeyIdentifier(caCert).toASN1Primitive().getEncoded());
		// final Extension subjectKeyIdentifier = new Extension(Extension.subjectKeyIdentifier,
		// false,
		// extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()).toASN1Primitive()
		// .getEncoded());

	}
}
