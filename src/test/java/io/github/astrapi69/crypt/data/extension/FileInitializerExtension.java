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
package io.github.astrapi69.crypt.data.extension;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.crypt.data.factory.CertificateAlgorithmEntry;
import io.github.astrapi69.crypt.data.processor.KeyPairEntry;

public class FileInitializerExtension
{

	private static <T> List<T> initializeFile(File csvFile, Supplier<List<T>> emptyListSupplier,
		Function<File, List<T>> readEntriesFromCsv, String headerLine) throws IOException
	{

		List<T> entries;

		if (!csvFile.exists())
		{
			entries = emptyListSupplier.get();
			LineAppender.appendLines(csvFile, headerLine);
		}
		else
		{
			entries = readEntriesFromCsv.apply(csvFile);
		}

		return entries;
	}

	private static <T> Function<File, List<T>> wrapCsvReader(
		FunctionWithIOException<File, List<T>> function)
	{
		return file -> {
			try
			{
				return function.apply(file);
			}
			catch (IOException e)
			{
				throw new RuntimeException(e);
			}
		};
	}

	@FunctionalInterface
	public interface FunctionWithIOException<T, R>
	{
		R apply(T t) throws IOException;
	}

	public static List<KeyPairEntry> getKeyPairEntries(File invalidCsvFile) throws IOException
	{
		return initializeFile(invalidCsvFile, ListFactory::newArrayList,
			wrapCsvReader(CsvExtensions::readKeyPairEntriesFromCsv), "algorithm,keysize");
	}

	public static List<CertificateAlgorithmEntry> inializeFile(File validSignatureAlgorithmsCsvFile)
		throws IOException
	{
		return initializeFile(validSignatureAlgorithmsCsvFile, ListFactory::newArrayList,
			wrapCsvReader(CsvExtensions::readCertificateAlgorithmEntryFromCsv),
			"keypair-algorithm,signature-algorithm");
	}
}
