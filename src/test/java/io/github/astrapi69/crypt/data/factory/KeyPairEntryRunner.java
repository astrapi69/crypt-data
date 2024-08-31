package io.github.astrapi69.crypt.data.factory;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;

import io.github.astrapi69.crypt.data.extension.LineAppender;
import lombok.extern.java.Log;

@Log
public class KeyPairEntryRunner implements Runnable
{
	final KeyPairEntry keyPairEntry;
	final File validCsvFile;
	final File invalidCsvFile;

	public KeyPairEntryRunner(final KeyPairEntry keyPairEntry, File validCsvFile,
		File invalidCsvFile)
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
