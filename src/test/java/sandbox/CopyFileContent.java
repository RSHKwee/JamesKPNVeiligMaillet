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
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;

import org.apache.james.core.builder.MimeMessageBuilder;
import org.apache.mailet.Mail;
import org.apache.mailet.MailetContext;
import org.apache.mailet.MailetException;
import org.apache.mailet.base.test.FakeMail;
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

    Path tempPath = Paths.get(System.getProperty("java.io.tmpdir"));

    Path zipPath = Paths.get("F:\\dev\\James Mailets\\JamesKPNVeiligMaillet\\src\\test\\resources\\eicar_com.zip");
    // Path zipPath = Paths.get("D:\\Dev\\Github\\James
    // Maillets\\KPNVeilig\\src\\test\\resources\\eicar_com.zip");
    // Path sourcePath = Paths.get("bronbestand.txt");
    String gezipt = "eicar.com";
    String geziptDir = tempPath.toAbsolutePath().toString();
    Path destinationPath = Paths.get(geziptDir + gezipt);

    destinationPath = GetZippedFile(zipPath, geziptDir, gezipt);

    try {
      mailetContext = mock(MailetContext.class);
      //@formatter:off
      mailetConfig = FakeMailetConfig.builder()
          .mailetName("KPNVeiligScan").mailetContext(mailetContext)
          .setProperty("kpnVeiligPath", "C:\\Program Files (x86)\\KPN Veilig\\fsscan.exe")
          .setProperty("tmpDir", tempPath.toAbsolutePath().toString())
          .setProperty("quarantineDir", "target/quarantine")
          .build();
      //@formatter:on
//      Mail mail = createInfectedMail();
//      mailet = new KPNVeiligVirusScan();
//      mailet.init(mailetConfig);
//      KPNVeiligVirusScan spyMailet = spy(mailet);
//      spyMailet.service(mail);

      boolean result = scanFileWithKPNVScan(destinationPath);
      LOGGER.info("Scanresult: " + result);
    } catch (Exception e) {
      // TODO Auto-generated catch block
      LOGGER.error(e.getMessage());
      e.printStackTrace();
    }
  }

  static boolean scanFileWithKPNVScan(Path file) throws IOException, MailetException {
    String kpnVeiligPath = "C:\\Program Files (x86)\\KPN Veilig\\fsscan.exe";
    ProcessBuilder pb = new ProcessBuilder(kpnVeiligPath, file.toAbsolutePath().toString());

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

  // " *H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
  static private Mail createInfectedMail() throws MessagingException, IOException {
    // 1. Maak een MimeMessage
    MimeMessage mimeMessage;
    try {
      // String eicar =
      // "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
      String eicar = reverse("*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X");

      mimeMessage = MimeMessageBuilder.mimeMessageBuilder().setSubject("Test: EICAR Virus Test File")
          .setText("Hello world!").build();

      // 2. Stel basis headers in
      mimeMessage.setFrom("sender@example.com");
      mimeMessage.setRecipients(javax.mail.Message.RecipientType.TO, "recipient@example.com");
      mimeMessage.setSubject("Test: EICAR Virus Test File");

      // 3. Maak multipart bericht met tekst en bijlage
      MimeMultipart multipart = new MimeMultipart();

      // 3a. Tekstgedeelte
      MimeBodyPart textPart = new MimeBodyPart();
      textPart.setText("Dit is een testmail met een veilig testvirus als bijlage.");
      multipart.addBodyPart(textPart);

      // 3b. EICAR bijlage
      MimeBodyPart attachmentPart = new MimeBodyPart();

      // Maak datasource voor de bijlage
      ByteArrayDataSource ds = new ByteArrayDataSource(eicar.getBytes(), "application/octet-stream");
      attachmentPart.setDataHandler(new javax.activation.DataHandler(ds));
      attachmentPart.setFileName("eicar.com");
      multipart.addBodyPart(attachmentPart);

      // 4. Zet de content in het bericht
      mimeMessage.setContent(multipart);

      // 5. Maak het Mail object
      Mail mail;
      //@formatter:off
      mail = FakeMail.builder()
          .name("virus-test-mail")
          .mimeMessage(mimeMessage)
          .sender("sender@domain.com")
          .recipient("recipient@domain.com")
          .build();
      //@formatter:on
      return mail;
    } catch (Exception e) {
      // TODO Auto-generated catch block
      // e.printStackTrace();
      LOGGER.info(e.getMessage().toString());
    }
    return null;
  }

  static private Path GetZippedFile(Path zipPath, String a_DestDir, String a_ZippedFile) {
    String gezipt = a_ZippedFile;
    String geziptDir = a_DestDir;
    Path destinationPath = Paths.get(geziptDir + "\\" + gezipt);
    // Path destinationPath = Paths.get("f:\\dev" + "\\" + gezipt);
    Path entryPath = null;

    // Create a filesystem for the ZIP file
    try (FileSystem zipFs = FileSystems.newFileSystem(zipPath, (ClassLoader) null)) {
      // Get path to entry inside the ZIP
      entryPath = zipFs.getPath(gezipt);

      // Now you can use standard Files methods
      if (Files.exists(entryPath)) {
        LOGGER.info("Entry path in ZIP: " + entryPath + " Size: " + Files.size(entryPath) + " bytes");

        // Read content directly
        List<String> lines = Files.readAllLines(entryPath);
        // LOGGER.info("First line: " + lines.get(0));

        Path tempPath = Paths.get(System.getProperty("java.io.tmpdir"), "test.txt");
        Files.write(tempPath, lines);

        // Files.write(destinationPath, lines);
        // @formatter:off
        Files.write(destinationPath, lines, 
            StandardOpenOption.CREATE, 
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE);
        // @formatter:on
        LOGGER.info("Bestand succesvol gekopieerd naar: " + destinationPath.toAbsolutePath());
      }
    } catch (IOException e) {
      LOGGER.error("Fout: " + e.getCause());
      LOGGER.error("Fout: " + e.getMessage());
    }
    return destinationPath;
  }

  static private String reverse(String str) {
    if (str.isEmpty()) {
      return str;
    }
    return reverse(str.substring(1)) + str.charAt(0);
  }
}
