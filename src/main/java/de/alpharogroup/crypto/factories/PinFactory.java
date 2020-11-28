package de.alpharogroup.crypto.factories;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;

import lombok.NonNull;
import de.alpharogroup.collections.list.ListFactory;

public final class PinFactory
{
	private PinFactory()
	{
	}

	public static List<String> newPins(@NonNull List<LocalDate> localDates,
		@NonNull List<String> datePatterns)
	{
		List<String> result = ListFactory.newArrayList();

		for (LocalDate localDate : localDates)
		{
			for (String datePattern : datePatterns)
			{
				result.add(localDate.format(DateTimeFormatter.ofPattern(datePattern)));
			}
		}
		result.sort(Comparator.naturalOrder());
		return result;
	}
}
