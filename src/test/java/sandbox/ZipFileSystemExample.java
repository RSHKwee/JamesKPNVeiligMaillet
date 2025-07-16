package sandbox;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

public class ZipFileSystemExample {
  public static void main(String[] args) throws IOException {
    Path zipPath = Paths.get("F:\\dev\\James Mailets\\JamesKPNVeiligMaillet\\src\\test\\resources\\eicar_com.zip");

    // Create a filesystem for the ZIP file
    try (FileSystem zipFs = FileSystems.newFileSystem(zipPath, (ClassLoader) null)) {
      // Get path to entry inside the ZIP
      Path entryPath = zipFs.getPath("eicar.com");

      // Now you can use standard Files methods
      if (Files.exists(entryPath)) {
        System.out.println("Entry path in ZIP: " + entryPath);
        System.out.println("Size: " + Files.size(entryPath) + " bytes");

        // Read content directly
        List<String> lines = Files.readAllLines(entryPath);
        System.out.println("First line: " + lines.get(0));
      }
    }
  }
}