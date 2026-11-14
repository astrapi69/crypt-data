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

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * What {@link PrivateKeyReader#readPrivateKey(File)} writes to standard error for a DER key file,
 * measured in a JVM of its own with the default {@code java.util.logging} configuration: that is
 * what a command line that reads a key shows its user (#144, astrapi69/mystic-crypt-ui#968). A
 * redirected {@code System.err} in this JVM would not show it, because the console handler of the
 * root logger holds the standard error it found when it was created.
 */
class PrivateKeyReaderProbeOutputTest
{

	@TempDir
	Path tempDir;

	/**
	 * Entry point of the JVM the tests start: reads the given file and prints the algorithm of the
	 * private key, or {@code none} when nothing was read
	 *
	 * @param args
	 *            the path of the key file
	 * @throws Exception
	 *             if the file cannot be read
	 */
	public static void main(final String[] args) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		PrivateKey privateKey = PrivateKeyReader.readPrivateKey(new File(args[0]));
		System.out.println(privateKey == null ? "none" : privateKey.getAlgorithm());
	}

	/**
	 * What the JVM the test started gave back
	 *
	 * @param exitCode
	 *            its exit code
	 * @param standardOutput
	 *            what it printed on standard output
	 * @param standardError
	 *            what it printed on standard error
	 */
	record Reading(int exitCode, String standardOutput, String standardError) {
	}

	/**
	 * A key of one of the algorithms the reader probes, PKCS#8 encoded as a DER file
	 *
	 * @param algorithm
	 *            the algorithm the key is generated with
	 * @param keySize
	 *            its size
	 * @param probesFailedBefore
	 *            how many probed algorithms come before it and fail on it
	 */
	record KeyCase(String algorithm, int keySize, int probesFailedBefore) {
		@Override
		public String toString()
		{
			return algorithm + " " + keySize;
		}
	}

	static Stream<KeyCase> readableKeys()
	{
		return Stream.of(new KeyCase("DH", 2048, 0), new KeyCase("DSA", 2048, 1),
			new KeyCase("EC", 256, 2), new KeyCase("RSA", 2048, 3));
	}

	@ParameterizedTest(name = "a {0} key read correctly")
	@MethodSource("readableKeys")
	void aKeyReadCorrectly_writesOneWarningForEveryProbeThatFailedBefore(final KeyCase keyCase)
		throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(keyCase.algorithm());
		generator.initialize(keyCase.keySize());
		Path keyFile = tempDir.resolve(keyCase.algorithm() + ".der");
		Files.write(keyFile, generator.generateKeyPair().getPrivate().getEncoded());

		Reading reading = readInAJvmOfItsOwn(keyFile);

		assertEquals(0, reading.exitCode(), reading.standardError());
		assertEquals(keyCase.algorithm(), reading.standardOutput().strip());
		assertEquals(keyCase.probesFailedBefore(), warningsIn(reading).size(),
			reading.standardError());
	}

	@Test
	void unreadableBytes_writeOneWarningWithAStackTraceForEveryProbedAlgorithm() throws Exception
	{
		Path keyFile = tempDir.resolve("not-a-key.der");
		Files.write(keyFile, "this is not a private key".getBytes(StandardCharsets.US_ASCII));

		Reading reading = readInAJvmOfItsOwn(keyFile);

		assertEquals(0, reading.exitCode(), reading.standardError());
		assertEquals("none", reading.standardOutput().strip());
		assertEquals(
			List.of("WARNING: Given private key file is not stored in 'DiffieHellman' algorithm",
				"WARNING: Given private key file is not stored in 'DSA' algorithm",
				"WARNING: Given private key file is not stored in 'EC' algorithm",
				"WARNING: Given private key file is not stored in 'RSASSA-PSS' algorithm",
				"WARNING: Given private key file is not stored in 'RSA' algorithm"),
			warningsIn(reading));
		assertEquals(5, stackTracesIn(reading), reading.standardError());
	}

	private static List<String> warningsIn(final Reading reading)
	{
		return reading.standardError().lines().filter(line -> line.startsWith("WARNING:"))
			.collect(Collectors.toList());
	}

	private static long stackTracesIn(final Reading reading)
	{
		return reading.standardError().lines().filter(line -> line.startsWith("java.security."))
			.count();
	}

	private Reading readInAJvmOfItsOwn(final Path keyFile) throws Exception
	{
		String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
		String classPath = Stream
			.of(System.getProperty("java.class.path"), System.getProperty("jdk.module.path"))
			.filter(path -> path != null && !path.isBlank())
			.collect(Collectors.joining(File.pathSeparator));
		Path standardOutput = tempDir.resolve(keyFile.getFileName() + ".out");
		Path standardError = tempDir.resolve(keyFile.getFileName() + ".err");
		ProcessBuilder builder = new ProcessBuilder(java, "-cp", classPath,
			PrivateKeyReaderProbeOutputTest.class.getName(), keyFile.toString())
				.redirectOutput(standardOutput.toFile()).redirectError(standardError.toFile());
		// options a machine sets for every JVM make it say so on standard error, which is not the
		// reader's output
		builder.environment().remove("JAVA_TOOL_OPTIONS");
		builder.environment().remove("JDK_JAVA_OPTIONS");
		builder.environment().remove("_JAVA_OPTIONS");
		Process process = builder.start();
		if (!process.waitFor(60, TimeUnit.SECONDS))
		{
			process.destroyForcibly();
			throw new AssertionError(
				"the JVM that reads " + keyFile + " did not end in 60 seconds");
		}
		return new Reading(process.exitValue(),
			Files.readString(standardOutput, StandardCharsets.UTF_8),
			Files.readString(standardError, StandardCharsets.UTF_8));
	}
}
