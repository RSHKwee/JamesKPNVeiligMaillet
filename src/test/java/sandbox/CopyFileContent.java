package sandbox;

import static org.mockito.Mockito.mock;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.mail.MessagingException;

import org.apache.mailet.MailetContext;
import org.apache.mailet.MailetException;
import org.apache.mailet.base.test.FakeMailetConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kwee.james.mailets.KPNVeiligVirusScan;

public class CopyFileContent {
  private static final Logger LOGGER = LoggerFactory.getLogger(CopyFileContent.class);

  public static void main(String[] args) throws IOException {
    KPNVeiligVirusScan mailet;
    MailetContext mailetContext;
    FakeMailetConfig mailetConfig;

//    Path zipPath = Paths.get("F:\\dev\\James Mailets\\JamesKPNVeiligMaillet\\src\\test\\resources\\eicar_com.zip");
    Path zipPath = Paths.get("D:\\Dev\\Github\\James Maillets\\KPNVeilig\\src\\test\\resources\\eicar_com.zip");
    // Path sourcePath = Paths.get("bronbestand.txt");
    String gezipt = "eicar.com";
    Path destinationPath = Paths.get(gezipt);
    Path entryPath = null;

    // Create a filesystem for the ZIP file
    try (FileSystem zipFs = FileSystems.newFileSystem(zipPath, (ClassLoader) null)) {
      // Get path to entry inside the ZIP
      entryPath = zipFs.getPath(gezipt);

      // Now you can use standard Files methods
      if (Files.exists(entryPath)) {
        // LOGGER.info("Entry path in ZIP: " + entryPath);
        LOGGER.info("Entry path in ZIP: " + entryPath + " Size: " + Files.size(entryPath) + " bytes");

        // Read content directly
        List<String> lines = Files.readAllLines(entryPath);
        // LOGGER.info("First line: " + lines.get(0));

        Files.write(destinationPath, lines);

        LOGGER.info("Bestand succesvol gekopieerd naar: " + destinationPath.toAbsolutePath());
      }
    } catch (IOException e) {
      LOGGER.error("Fout: " + e.getMessage());
    }

    try {
      mailetContext = mock(MailetContext.class);
      mailetConfig = FakeMailetConfig.builder()
          .mailetName("KPNVeiligScan")
          .mailetContext(mailetContext)
          .setProperty("kpnVeiligPath", "C:\\Program Files (x86)\\KPN Veilig\\fsscan.exe")
          .setProperty("tmpDir", "target\\tmp")
          .setProperty("quarantineDir", "target/quarantine")
          .build();

      // mailet = new KPNVeiligVirusScan();
      // mailet.init(mailetConfig);
      // KPNVeiligVirusScan spyMailet = spy(mailet);

      boolean result = scanFileWithKPNVScan(destinationPath);
      LOGGER.info("Scanresult: " + result);
    } catch (MessagingException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

  static boolean scanFileWithKPNVScan(Path file) throws IOException, MailetException {
    String kpnVeiligPath = "C:\\Program Files (x86)\\KPN Veilig\\fsscan.exe";
    ProcessBuilder pb = new ProcessBuilder(kpnVeiligPath,
        // "/ARCHIVE", // Scan binnen archives
        // "/DELETE", // Verwijder geïnfecteerde bestanden
        // "/REPORT=XML", // XML-formaat voor parsing
        file.toAbsolutePath().toString());
// "C:\Program Files (x86)\KPN Veilig\fsscan.exe" "%FILE%"
    LOGGER.debug("Commandline: " + pb.command().toString() + " " + file.toAbsolutePath());
    pb.redirectErrorStream(true);
    pb.inheritIO();
    try {
      Process process = pb.start();
      int procexit = process.waitFor();
      LOGGER.debug("Procexit result: " + procexit);
      // Wacht met timeout
      if (!process.waitFor(30000, TimeUnit.MILLISECONDS)) {
        process.destroyForcibly();
        throw new MailetException("KPN Veilig scan timeout exceeded");
      }

      // Parse exit code:
      // 0 = schoon, 1 = geïnfecteerd, andere codes = fout
      int exitCode = process.exitValue();
      LOGGER.info("Scan result: " + exitCode);

      if (exitCode > 1) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
          String line;
          while ((line = reader.readLine()) != null) {
            LOGGER.warn("KPN Veilig output: " + line);
          }
        }
        throw new MailetException("KPN Veilig scan failed with code: " + exitCode);
      }

      return exitCode == 3;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new MailetException("Scan interrupted", e);
    }
  }

}
