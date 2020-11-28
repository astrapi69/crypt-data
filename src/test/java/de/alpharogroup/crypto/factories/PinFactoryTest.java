package de.alpharogroup.crypto.factories;

import de.alpharogroup.collections.list.ListFactory;
import io.github.astrapi69.time.enums.DatePattern;
import org.testng.annotations.Test;

import java.time.LocalDate;
import java.util.List;

import static org.testng.Assert.*;

public class PinFactoryTest
{

	@Test
	public void testNewPins(){
		List<LocalDate> localDates;
		List<String> datePatterns;
		datePatterns = ListFactory.newArrayList(
			"ddMM",
			"MMdd",
			"MMyy",
			"yyyy"
		);
		localDates = ListFactory.newArrayList(
			LocalDate.of(1963, 11, 14),
			LocalDate.of(1967, 4, 18),
			LocalDate.of(1977, 5, 21),
			LocalDate.of(1981, 1, 19),
			LocalDate.of(1988, 3, 11)
		);
		List<String> pins = PinFactory.newPins(localDates, datePatterns);
		assertEquals(pins.size(), 20);
//		pins.stream().forEach(System.out::println);
	}
}
