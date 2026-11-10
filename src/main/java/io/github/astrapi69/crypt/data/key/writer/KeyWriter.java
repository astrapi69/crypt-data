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
package io.github.astrapi69.crypt.data.key.writer;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Key;
import java.util.Objects;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * The class {@link KeyWriter} is a utility class for write security keys in files.
 */
public final class KeyWriter
{

	private KeyWriter()
	{
	}

	/**
	 * Write the given {@link Key} into the given {@link File}.
	 *
	 * @param key
	 *            the security key
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             if the file cannot be opened or written
	 */
	public static void writeInPemFormat(final Key key, final File file) throws IOException
	{
		Objects.requireNonNull(file);
		StringWriter stringWriter = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
		pemWriter.writeObject(key);
		pemWriter.close();
		String pemFormat = stringWriter.toString();
		pemFormat = pemFormat.replaceAll("\\r\\n", "\\\n");
		// The JDK write throws the IOException this method declares when the write fails.
		// StoreFileExtensions.toFile from file-worker wrote through a PrintWriter, which swallows
		// it, so a full disk left an empty or cut off key file unreported (#125). PEM is ASCII.
		Files.writeString(file.toPath(), pemFormat, StandardCharsets.US_ASCII);
	}

}
