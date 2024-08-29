package io.github.astrapi69.crypt.data.extension;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

import io.github.astrapi69.collection.list.ListFactory;

public class LineAppender
{

	/**
	 * Appends the given lines to the given {@link File} object
	 *
	 * @param file
	 *            The source file
	 * @param lineToAppend
	 *            The lines to append
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void appendLines(File file, String... lineToAppend) throws IOException
	{
		Files.write(file.toPath(), ListFactory.newArrayList(lineToAppend),
			StandardOpenOption.APPEND, StandardOpenOption.CREATE);
	}

}
