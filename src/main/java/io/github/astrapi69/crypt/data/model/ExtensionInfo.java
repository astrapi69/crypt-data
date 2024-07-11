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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;

import lombok.AccessLevel;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

/**
 * Data class representing extension information
 */
@Data
@RequiredArgsConstructor
@SuperBuilder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ExtensionInfo
{
	/**
	 * The identifier of the extension.
	 */
	String extensionId;

	/**
	 * Indicates whether the extension is critical.
	 */
	boolean critical;

	/**
	 * The value of the extension.
	 */
	String value;

	/**
	 * Converts an {@link ExtensionInfo} object to a {@link Extension} object.
	 *
	 * @param extensionInfo
	 *            the {@link ExtensionInfo} object to convert.
	 * @return the corresponding {@link Extension} object.
	 */
	public static Extension toExtension(final ExtensionInfo extensionInfo)
	{
		ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(extensionInfo.getExtensionId());
		byte[] extensionValue = extensionInfo.getValue().getBytes();
		ASN1OctetString value = new DEROctetString(extensionValue);
		return new Extension(oid, extensionInfo.isCritical(), value);
	}

	/**
	 * Factory method to create an {@link ExtensionInfo} object from a {@link Extension} object.
	 *
	 * @param extension
	 *            the {@link Extension} object to convert.
	 * @return the corresponding {@link ExtensionInfo} object.
	 */
	public static ExtensionInfo fromExtension(final Extension extension)
	{
		String extensionId = extension.getExtnId().getId();
		boolean critical = extension.isCritical();
		String value = new String(extension.getExtnValue().getOctets());

		return ExtensionInfo.builder().extensionId(extensionId).critical(critical).value(value)
			.build();
	}
}
