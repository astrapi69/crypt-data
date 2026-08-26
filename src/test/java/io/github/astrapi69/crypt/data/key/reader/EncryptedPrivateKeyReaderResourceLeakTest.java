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
package io.github.astrapi69.crypt.data.key.reader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Regression test for the file descriptor leak in
 * {@link EncryptedPrivateKeyReader#getKeyPair(File, String)}: the PEM parser was closed with a
 * plain call after {@code readObject()}, so a malformed PEM body - which makes {@code readObject()}
 * throw - left the underlying reader open.
 * <p>
 * The check reads {@code /proc/self/fd} and counts the descriptors that point at the file just
 * parsed, which makes an open handle directly observable instead of inferring it from a total
 * descriptor count. The test skips itself where that directory does not exist.
 */
class EncryptedPrivateKeyReaderResourceLeakTest
{

	/**
	 * A PEM body with well formed markers and a payload that is not valid base64 encoded DER, so
	 * {@link org.bouncycastle.openssl.PEMParser#readObject()} fails while parsing it
	 */
	private static final String MALFORMED_PEM = """
		-----BEGIN RSA PRIVATE KEY-----
		Proc-Type: 4,ENCRYPTED
		DEK-Info: DES-EDE3-CBC,0123456789ABCDEF

		this is not base64 encoded der content at all
		-----END RSA PRIVATE KEY-----
		""";

	/** The directory the running process exposes its open file descriptors under, on Linux */
	private static final Path PROC_SELF_FD = Path.of("/proc/self/fd");

	@BeforeEach
	void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	@Test
	void aFailedReadOfAMalformedPemFileLeavesNoOpenDescriptorForThatFile(@TempDir File temporaryDir)
		throws IOException
	{
		assumeTrue(Files.isDirectory(PROC_SELF_FD),
			"this check reads " + PROC_SELF_FD + ", which only exists on Linux");

		File malformedPemFile = new File(temporaryDir, "malformed-encrypted-key.pem");
		Files.writeString(malformedPemFile.toPath(), MALFORMED_PEM, StandardCharsets.UTF_8);
		Path malformedPemPath = malformedPemFile.toPath().toRealPath();

		assertThrows(IOException.class,
			() -> EncryptedPrivateKeyReader.getKeyPair(malformedPemFile, "secret"),
			"a malformed PEM body must surface as an IOException");

		assertEquals(0, openDescriptorsFor(malformedPemPath),
			"the parser must be closed on the exception path as well, but the process still holds "
				+ "an open descriptor for " + malformedPemPath);
	}

	/**
	 * Counts the descriptors this process currently has open on the given file.
	 *
	 * @param file
	 *            the resolved real path of the file to look for
	 * @return the number of open descriptors pointing at that file
	 * @throws IOException
	 *             if the descriptor directory cannot be listed
	 */
	private static long openDescriptorsFor(final Path file) throws IOException
	{
		try (Stream<Path> descriptors = Files.list(PROC_SELF_FD))
		{
			List<Path> targets = descriptors
				.map(EncryptedPrivateKeyReaderResourceLeakTest::linkTarget)
				.filter(target -> target != null).toList();
			return targets.stream().filter(file::equals).count();
		}
	}

	/**
	 * Resolves one entry of the descriptor directory to the file it points at. Descriptors come and
	 * go while the directory is being listed, so an entry that has already vanished is reported as
	 * no target rather than failing the whole scan.
	 *
	 * @param descriptor
	 *            the entry below {@code /proc/self/fd}
	 * @return the file the descriptor points at, or null if it cannot be resolved
	 */
	private static Path linkTarget(final Path descriptor)
	{
		try
		{
			return Files.readSymbolicLink(descriptor);
		}
		catch (final IOException | UncheckedIOException vanished)
		{
			return null;
		}
	}
}
