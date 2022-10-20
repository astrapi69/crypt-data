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
