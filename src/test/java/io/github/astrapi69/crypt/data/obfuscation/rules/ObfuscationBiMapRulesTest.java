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
package io.github.astrapi69.crypt.data.obfuscation.rules;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanVerifier;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import io.github.astrapi69.crypt.data.obfuscation.ObfuscationBiMapTestData;
import io.github.astrapi69.evaluate.object.evaluator.EqualsHashCodeAndToStringEvaluator;

/**
 * The unit test class for the class {@link ObfuscationBiMapRules}
 */
public class ObfuscationBiMapRulesTest
{

	/**
	 * Test method for {@link ObfuscationBiMapRules#equals(Object)} ,
	 * {@link ObfuscationBiMapRules#hashCode()} and {@link ObfuscationBiMapRules#toString()}
	 */
	@Test
	public void testEqualsHashcodeAndToString()
	{

		boolean expected;
		boolean actual;
		Map<String, String> charmap;
		BiMap<String, String> obfuscationRules;
		Map<String, String> map;
		ObfuscationBiMapRules<String, String> first;
		ObfuscationBiMapRules<String, String> second;
		ObfuscationBiMapRules<String, String> third;
		ObfuscationBiMapRules<String, String> fourth;

		charmap = new HashMap<>();

		charmap.put("1", "O");
		charmap.put("2", "Tw");
		charmap.put("3", "Th");
		charmap.put("4", "Fo");
		charmap.put("5", "Fi");
		charmap.put("6", "Si");
		charmap.put("7", "Se");
		charmap.put("8", "E");
		charmap.put("9", "N");
		obfuscationRules = HashBiMap.create(charmap);

		map = new HashMap<>();

		map.put("1", "O");

		first = ObfuscationBiMapRules.<String, String> builder().obfuscationRules(obfuscationRules)
			.build();
		second = new ObfuscationBiMapRules<>(HashBiMap.create(map));
		third = new ObfuscationBiMapRules<>(obfuscationRules);
		fourth = new ObfuscationBiMapRules<>(obfuscationRules);

		actual = EqualsHashCodeAndToStringEvaluator.evaluateEqualsHashcodeAndToString(first, second,
			third, fourth);
		expected = true;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link ObfuscationBiMapRules}
	 */
	@Test
	public void testWithBeanTester()
	{
		BiMap<Character, Character> obfuscationRules = ObfuscationBiMapTestData
			.getSmallestBiMapObfuscationRules();
		BeanVerifier.forClass(ObfuscationBiMapRules.class).editSettings()
			.registerFactory(ObfuscationBiMapRules.class,
				() -> ObfuscationBiMapRules.<Character, Character> builder()
					.obfuscationRules(obfuscationRules).build())
			.edited().verifyGettersAndSetters().verifyEqualsAndHashCode().verifyToString();
	}

}
