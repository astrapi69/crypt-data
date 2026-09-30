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
package io.github.astrapi69.crypt.data.hex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.commons.codec.binary.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.meanbean.test.BeanTester;

/**
 * The unit test class for the class {@link HexExtensions}
 */
public class HexExtensionsTest
{

	/**
	 * Test method for {@link HexExtensions#decodeHex(char[])}
	 *
	 */
	@Test
	public void testDecodeHex()
	{
		String expected;
		String actual;
		char[] actualCharArray;
		byte[] decoded;

		expected = "Secret message";
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(expected));
		decoded = HexExtensions.decodeHex(actualCharArray);
		actual = new String(decoded);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#decodeHex(byte[])}
	 *
	 */
	@Test
	public void testDecodeHexCharacterArray()
	{
		String expected;
		String actual;
		char[] actualCharArray;
		byte[] decoded;

		expected = "Secret message";
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(expected));
		decoded = HexExtensions.decodeHex(actualCharArray);
		actual = HexExtensions.decodeHex(decoded);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#decodeHex(String)}
	 *
	 */
	@Test
	public void testDecodeHexString()
	{
		String actual;
		String expected;
		String hexString;
		String secretMessage;

		secretMessage = "Secret message";
		hexString = "536563726574206d657373616765";
		actual = HexExtensions.decodeHex(hexString);
		expected = secretMessage;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#decodeHexToString(char[])}
	 *
	 */
	@Test
	public void testDecodeHexToString()
	{
		String expected;
		String actual;
		char[] actualCharArray;

		expected = "Secret message";
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(expected));
		actual = HexExtensions.decodeHexToString(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#encodeHex(byte[])}
	 */
	@Test
	public void testEncodeHex()
	{
		String actual;
		String expected;
		String secretMessage;
		char[] actualCharArray;

		secretMessage = "Secret message";
		expected = "536563726574206d657373616765";
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(secretMessage));
		actual = new String(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#encodeHex(byte[], boolean)}
	 */
	@Test
	public void testEncodeHexBoolean()
	{
		String actual;
		String expected;
		String secretMessage;
		char[] actualCharArray;

		secretMessage = "Secret message";
		expected = "536563726574206d657373616765";
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(secretMessage), true);
		actual = new String(actualCharArray);
		assertEquals(expected, actual);
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(secretMessage), false);
		actual = new String(actualCharArray);
		assertEquals(expected.toUpperCase(), actual);
	}

	/**
	 * Test method for {@link HexExtensions#encodeHex(String, Charset, boolean)}
	 */
	@Test
	public void testEncodeHexStringCharsetBoolean()
	{
		String actual;
		String expected;
		String hexString;
		String secretMessage;

		secretMessage = "Secret message";
		hexString = "536563726574206d657373616765";
		actual = HexExtensions.encodeHex(secretMessage, StandardCharsets.UTF_8, true);
		expected = hexString;
		assertEquals(expected, actual);

		secretMessage = "Secret message";
		hexString = "536563726574206D657373616765";
		actual = HexExtensions.encodeHex(secretMessage, StandardCharsets.UTF_8, false);
		expected = hexString;
		assertEquals(expected, actual);

		secretMessage = "Secret message";
		hexString = "536563726574206D657373616765";
		actual = HexExtensions.encodeHex(secretMessage, null, false);
		expected = hexString;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#encodeHex(String)}
	 */
	@Test
	public void testEncodeString()
	{
		String actual;
		String expected;
		String secretMessage;
		char[] actualCharArray;

		secretMessage = "Secret message";
		expected = "536563726574206d657373616765";
		actualCharArray = HexExtensions.encodeHex(secretMessage);
		actual = new String(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#toHex(int)}
	 */
	@Test
	public void testToHex()
	{
		char actual;

		actual = HexExtensions.toHex(5);
		assertTrue(actual == '5');
		actual = HexExtensions.toHex(10);
		assertTrue(actual == 'A');
	}

	/**
	 * Test method for {@link HexExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(HexExtensions.class);
	}

	/**
	 * Reproduction of #51: no public method of {@link HexExtensions} may declare an exception type
	 * from commons-codec. That dependency is an implementation detail, so a consumer cannot see the
	 * type - it can neither catch it nor compile a call that declares it
	 */
	@Test
	public void noPublicMethodDeclaresAnExceptionFromCommonsCodec()
	{
		List<String> leaking = Arrays.stream(HexExtensions.class.getDeclaredMethods())
			.filter(method -> Modifier.isPublic(method.getModifiers()))
			.filter(method -> Arrays.stream(method.getExceptionTypes())
				.anyMatch(type -> type.getName().startsWith("org.apache.commons.codec.")))
			.map(Method::toGenericString).collect(Collectors.toList());

		assertEquals(List.of(), leaking);
	}

	/**
	 * Input that is not hexadecimal is refused with an {@link IllegalArgumentException} that says
	 * why, by every decoding method
	 *
	 * @param caseName
	 *            the name of the case, shown in the report
	 * @param input
	 *            the input that is not hexadecimal
	 * @param reason
	 *            a part of the message that names the reason
	 */
	@ParameterizedTest(name = "{0}")
	@CsvSource(delimiter = '|', value = { "odd number of digits | abc | length not even: 3",
			"a character that is no hex digit | zz | not a hexadecimal digit: \"z\"",
			"a valid digit followed by an invalid one | 0g | not a hexadecimal digit: \"g\"",
			"a blank between digits | 0a 1 | not a hexadecimal digit: \" \"" })
	public void inputThatIsNotHexadecimalIsRefusedWithTheReason(String caseName, String input,
		String reason)
	{
		List<Function<String, Object>> decoders = List.of(
			value -> HexExtensions.decodeHex(value.toCharArray()),
			value -> HexExtensions.decodeHex(value),
			value -> HexExtensions.decodeHexToString(value.toCharArray()));

		for (Function<String, Object> decoder : decoders)
		{
			IllegalArgumentException refusal = assertThrows(IllegalArgumentException.class,
				() -> decoder.apply(input));
			assertTrue(refusal.getMessage().contains(reason), refusal.getMessage());
		}
	}

	/**
	 * Boundary: the empty input decodes to nothing, and upper and lower case digits decode alike
	 */
	@Test
	public void emptyInputDecodesToNothingAndCaseDoesNotMatter()
	{
		assertArrayEquals(new byte[0], HexExtensions.decodeHex(new char[0]));
		assertEquals("", HexExtensions.decodeHex(""));
		assertArrayEquals(new byte[] { (byte)0xAB, (byte)0xCD },
			HexExtensions.decodeHex("abCD".toCharArray()));
		assertArrayEquals(HexExtensions.decodeHex("ABCD".toCharArray()),
			HexExtensions.decodeHex("abcd".toCharArray()));
	}
}
