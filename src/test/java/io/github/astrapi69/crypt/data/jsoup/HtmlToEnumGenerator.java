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
package io.github.astrapi69.crypt.data.jsoup;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.file.system.SystemFileExtensions;

public class HtmlToEnumGenerator
{

	public static void main(String[] args) throws IOException
	{
		// Load the HTML file
		File userHomeDir = SystemFileExtensions.getUserHomeDir();
		File devTmpDir = PathFinder.getRelativePath(userHomeDir, "dev", "tmp");
		File htmlInput = PathFinder.getRelativePath(devTmpDir, "standard-names.html");
		System.out.println(htmlInput.exists());
		Document doc = Jsoup.parse(htmlInput, "UTF-8");

		// Dictionary to hold all algorithms
		Map<String, List<String>> algorithms = new HashMap<>();
		Map<String, Map<String, String>> algorithmMap = new HashMap<>();

		// Process each section
		Elements sections = doc.select("h2");
		for (Element section : sections)
		{
			String category = section.text().replaceAll("[<>\\-/\\.]", "_").replace(" ", "");
			Element sibling = section.nextElementSibling();

			while (sibling != null && !sibling.tagName().equals("h2"))
			{
				if (sibling.tagName().equals("table"))
				{
					Map<String, String> values = new HashMap<>();
					List<String> algos = new ArrayList<>();
					Elements rows = sibling.select("tr");
					for (int i = 1; i < rows.size(); i++)
					{ // Skip the header row
						Element row = rows.get(i);
						Elements columns = row.select("th");
						String algorithmName = null;
						if (!columns.isEmpty())
						{
							algorithmName = columns.get(0).text().trim();
							algos.add(algorithmName);
							values.put(algorithmName, null);
						}
						Elements tds = row.select("td");
						if (!tds.isEmpty())
						{
							String description = tds.get(0).text().trim();
							values.put(algorithmName, description);
						}
					}
					algorithms.put(category, algos);
					algorithmMap.put(category, values);
				}
				sibling = sibling.nextElementSibling();
			}
		}

		for (Map.Entry<String, Map<String, String>> entry : algorithmMap.entrySet())
		{
			int count = 0;
			String key = entry.getKey();
			String enumName = key.replaceAll("[<>\\-/\\.]", "_");
			Map<String, String> entryValue = entry.getValue();
			int size = entryValue.size();
			File file = new File(devTmpDir, enumName + ".java");
			StringBuilder sb = new StringBuilder();
			System.out.println("public enum " + enumName + " {");
			sb.append("public enum ").append(enumName).append(" {\n");
			for (Map.Entry<String, String> algo : entryValue.entrySet())
			{
				count++;
				if (count == size)
				{
					System.out.println(count + " is last " + size);
				}
				if (algo != null)
				{
					String algorithmName = algo.getKey();
					String description = algo.getValue();
					String enumConstant = algorithmName.toUpperCase().replaceAll("[<>\\-\\./]",
						"_");
					if (enumConstant.contains(" "))
					{
						String[] split = enumConstant.split(" ");
						String[] algorithmNames = algorithmName.split(" ");
						for (int i = 0; i < split.length; i++)
						{

							System.out.println("    " + split[i] + "(" + description + "),\n");
							sb.append("    ").append(split[i]).append("(\"")
								.append(algorithmNames[i]).append("\", ").append("\"")
								.append(description).append("\"").append(")").append(",\n");
						}
					}
					else
					{
						System.out.println("    " + enumConstant + "(" + description + "),\n");
						sb.append("    ").append(enumConstant).append("(\"").append(algorithmName)
							.append("\", ").append("\"").append(description).append("\"")
							.append(")").append(",\n");
					}
				}
			}
			sb.append(";\n");
			System.out.println("private final String algorithm;\n");
			System.out.println("private final String description;\n");
			System.out.println(enumName + "(final String algorithm, final String description)\n"
				+ "\t{\n" + "\t\tthis.algorithm = algorithm;\n"
				+ "\t\tthis.description = description;\n" + "\t}\n");
			System.out.println("    \n}\n");
			sb.append("private final String algorithm;\n");
			sb.append("private final String description;\n");
			sb.append(enumName + "(final String algorithm, final String description)\n" + "\t{\n"
				+ "\t\tthis.algorithm = algorithm;\n" + "\t\tthis.description = description;\n"
				+ "\t}\n");
			sb.append("    \n}\n"); // Add a semicolon before closing the enum
			// Save to file
			try
			{
				Files.write(file.toPath(), sb.toString().getBytes());
			}
			catch (IOException e)
			{
				e.printStackTrace();
			}
		}


	}
}
