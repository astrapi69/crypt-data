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
package io.github.astrapi69.crypt.data.processor.keypair;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;

import io.github.astrapi69.crypt.data.extension.LineAppender;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;
import lombok.extern.java.Log;

@Log
@Getter
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class KeyPairEntryRunner implements Runnable
{
	KeyPairEntry keyPairEntry;
	File validCsvFile;
	File invalidCsvFile;

	public KeyPairEntryRunner(final @NonNull KeyPairEntry keyPairEntry,
		final @NonNull File validCsvFile, final @NonNull File invalidCsvFile)
	{
		this.keyPairEntry = keyPairEntry;
		this.validCsvFile = validCsvFile;
		this.invalidCsvFile = invalidCsvFile;
	}

	@Override
	public void run()
	{
		String algorithm = keyPairEntry.getAlgorithm();
		Integer keySize = keyPairEntry.getKeySize();

		try
		{
			System.out
				.println("Start task with algorithm: " + algorithm + " , keysize: " + keySize);
			KeyPair keyPair = KeyPairFactory.newKeyPair(algorithm, keySize);
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();

			LineAppender.appendLines(validCsvFile, algorithm + "," + keySize);
			System.out.println(
				"Task " + "algorithm: " + algorithm + " , keysize: " + keySize + " completed");
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e)
		{
			try
			{
				LineAppender.appendLines(invalidCsvFile, algorithm + "," + keySize);
			}
			catch (IOException ex)
			{
				log.log(Level.WARNING, "Algorithm did not save to file " + invalidCsvFile.getName()
					+ " : " + keyPairEntry.getAlgorithm(), ex);
			}
			log.log(Level.WARNING, "Algorithm throws: " + keyPairEntry.getAlgorithm(), e);
		}
		catch (IOException e)
		{
			log.log(Level.WARNING, "Algorithm did not save to file " + validCsvFile.getName()
				+ " : " + keyPairEntry.getAlgorithm(), e);
		}
	}
}
