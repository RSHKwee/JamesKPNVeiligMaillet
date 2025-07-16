package sandbox;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import javax.mail.MessagingException;

import org.apache.mailet.MailetContext;
import org.apache.mailet.base.test.FakeMailetConfig;

import com.kwee.james.mailets.KPNVeiligVirusScan;

public class CopyFileContent {
  public static void main(String[] args) throws IOException {
    KPNVeiligVirusScan mailet;
    MailetContext mailetContext;
    FakeMailetConfig mailetConfig;

    Path zipPath = Paths.get("F:\\dev\\James Mailets\\JamesKPNVeiligMaillet\\src\\test\\resources\\eicar_com.zip");
    // Path sourcePath = Paths.get("bronbestand.txt");
    Path destinationPath = Paths.get("doelbestand.exe");

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

        Files.write(destinationPath, lines);
        System.out.println("Bestand succesvol gekopieerd naar: " + destinationPath.toAbsolutePath());

        mailetContext = mock(MailetContext.class);
        mailetConfig = FakeMailetConfig.builder().mailetName("KPNVeiligScan").mailetContext(mailetContext)
            .setProperty("kpnVeiligPath", "C:\\Program Files (x86)\\KPN Veilig\\fsscan.exe")
            .setProperty("tmpDir", "target\\tmp").setProperty("quarantineDir", "target/quarantine").build();
        mailet = new KPNVeiligVirusScan();
        try {
          mailet.init(mailetConfig);

          KPNVeiligVirusScan spyMailet = spy(mailet);

          boolean result = spyMailet.scanFileWithKPNVScan(destinationPath);
          System.out.println("Result: " + result);
        } catch (MessagingException e) {
          // TODO Auto-generated catch block
          e.printStackTrace();
        }
      }
    } catch (IOException e) {
      System.err.println("Fout: " + e.getMessage());
    }
  }
}