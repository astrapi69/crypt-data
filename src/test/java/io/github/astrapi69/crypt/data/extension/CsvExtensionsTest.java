package io.github.astrapi69.crypt.data.extension;

import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class CsvExtensionsTest {

    @Test
    void sortCsvByAlgorithmAndKeysize() throws IOException {

        File validCsvFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
                "new_valid_key_pair_algorithms.csv");
        // Example usage with a CSV file path
        Path csvFilePath = validCsvFile.toPath();
        CsvExtensions.sortCsvByAlgorithmAndKeysize(csvFilePath);
        System.out.println("CSV file sorted successfully.");
    }
}