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
/**
 * 
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package io.github.astrapi69.crypt.data.obfuscation.rule;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Comparator;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.collection.set.SetFactory;
import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;

/**
 * The unit test class for the class {@link ObfuscationOperationRuleComparator}.
 */
public class ObfuscationOperationRuleComparatorTest
{

	/** For use of the result of the comparator. */
	int actual;

	Character character;

	/** The comparator. */
	Comparator<ObfuscationOperationRule<Character, Character>> comparator;

	/** For use of the expected result. */
	boolean expected;
	Set<Integer> indexes;
	ObfuscationOperationRule<Character, Character> o1;
	ObfuscationOperationRule<Character, Character> o2;
	Operation operation;
	Character replaceWith;

	/**
	 * Test method for
	 * {@link ObfuscationOperationRuleComparator#compare(ObfuscationOperationRule, ObfuscationOperationRule)}.
	 */
	@Test
	public void testCompare()
	{
		comparator = new ObfuscationOperationRuleComparator();

		character = Character.valueOf('a');
		replaceWith = Character.valueOf('b');
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0, 2);

		o1 = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();

		o2 = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();

		actual = comparator.compare(o1, o2);
		expected = 0 == actual;
		assertTrue(expected);

		character = Character.valueOf('b');
		replaceWith = Character.valueOf('c');
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(2);

		o2 = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();

		actual = comparator.compare(o1, o2);
		expected = 0 > actual;
		assertTrue(expected);

		actual = comparator.compare(o2, o1);
		expected = 0 < actual;
		assertTrue(expected);
	}

}
