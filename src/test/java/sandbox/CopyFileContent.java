package sandbox;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.FileDataSource;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.apache.james.core.builder.MimeMessageBuilder;
import org.apache.james.mailets.kwee.KPNVeiligVirusScan;
import org.apache.mailet.Mail;
import org.apache.mailet.MailetContext;
import org.apache.mailet.MailetException;
import org.apache.mailet.base.test.FakeMail;
import org.apache.mailet.base.test.FakeMailetConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
      Mail mail = createInfectedMail();
      mailet = new KPNVeiligVirusScan();
      mailet.init(mailetConfig);
      KPNVeiligVirusScan spyMailet = spy(mailet);
      spyMailet.service(mail);

      // boolean result = scanFileWithKPNVScan(destinationPath);
      // LOGGER.info("Scanresult: " + result);
    } catch (Exception e) {
      // TODO Auto-generated catch block
      LOGGER.error(e.getMessage());
      // e.printStackTrace();
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

  static private Mail createInfectedMail() throws MessagingException, IOException {
    Properties props = new Properties();
    Session session = Session.getInstance(props);

    // 1. Maak een MimeMessage
    MimeMessage mimeMessage = new MimeMessage(session);
    try {
      // 2. Stel headers in
      mimeMessage.setHeader("Date", "Fri, 18 Jul 2025 14:14:03 +0200 (CEST)");
      mimeMessage.setHeader("Message-ID", "<1601756706.0.1752840843239>");
      mimeMessage.setSubject("Test: EICAR Virus Test File");
      mimeMessage.setFrom(new InternetAddress("sender@example.com"));
      mimeMessage.setRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"));
      mimeMessage.setHeader("MIME-Version", "1.0");

      // 3. Maak een multipart-bericht met boundary
      MimeMultipart multipart = new MimeMultipart("mixed");
      multipart.setSubType("mixed");

      // 4. Voeg de EICAR-bijlage toe
      MimeBodyPart attachmentPart = new MimeBodyPart();
      String eicarContent = reverse("*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X");

      attachmentPart.setContent(eicarContent, "application/octet-stream");
      attachmentPart.setFileName("eicar.com");
      attachmentPart.setHeader("Content-ID", "<c6d1e995-d4ac-4ab9-8b50-7f4568b9c499>");
      multipart.addBodyPart(attachmentPart);

      mimeMessage.setContent(multipart);

      // 5. Schrijf het bericht naar een bestand (of verstuur het)
      mimeMessage.writeTo(System.out); // Print naar console (of gebruik FileOutputStream)

      // 6. Maak het Mail object
      Mail mail;
      //@formatter:off
      mail = FakeMail.builder()
          .name("virus-test-mail")
          .mimeMessage(mimeMessage)
          .sender("sender@domain.com")
          .recipient("recipient@domain.com")
          .build();
      //@formatter:on

      Path tempPath = Paths.get(System.getProperty("java.io.tmpdir"));
      Path tempFile = Files.createTempFile(tempPath, "scan-", ".eml");
      try (OutputStream out = Files.newOutputStream(tempFile)) {
        mail.getMessage().writeTo(out);
      }
      LOGGER.debug("Virusmail File: " + tempFile.toAbsolutePath().toString());

      return mail;
    } catch (Exception e) {
      LOGGER.info(e.getMessage().toString());
    }
    return null;
  }

  static private Path GetZippedFile(Path zipPath, String a_DestDir, String a_ZippedFile) {
    String gezipt = a_ZippedFile;
    String geziptDir = a_DestDir;
    Path destinationPath = Paths.get(geziptDir + "\\" + gezipt);
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

  static private Mail createInfectedMailNew() throws MessagingException, IOException {
    // 1. Maak een MimeMessage
    MimeMessage mimeMessage;
    //@formatter:off
    mimeMessage = MimeMessageBuilder
        .mimeMessageBuilder()
        .setSubject("Test: EICAR Virus Test File")
        .setText("Hello world!")
        .build();
    //@formatter:on

    // 2. Base headers
    mimeMessage.setFrom("sender@example.com");
    mimeMessage.setRecipients(javax.mail.Message.RecipientType.TO, "recipient@example.com");

    MimeBodyPart messageBodyPart = new MimeBodyPart();
    Multipart multipart = new MimeMultipart();

    // Create file
    Path zipPath = Paths.get("F:\\dev\\James Mailets\\JamesKPNVeiligMaillet\\src\\test\\resources\\eicar_com.zip");
    Path tempPath = Paths.get(System.getProperty("java.io.tmpdir"));

    String gezipt = "eicar.com";
    String geziptDir = tempPath.toAbsolutePath().toString();
    Path destinationPath = Paths.get(geziptDir + gezipt);

    destinationPath = GetZippedFile(zipPath, geziptDir, gezipt);

    String file = destinationPath.toAbsolutePath().toString();
    String fileName = gezipt;

    DataSource source = new FileDataSource(file);
    messageBodyPart.setDataHandler(new DataHandler(source));
    messageBodyPart.setFileName(fileName);
    multipart.addBodyPart(messageBodyPart);

    mimeMessage.setContent(multipart);

    // 5. Create Mail object
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
  }

  static private String reverse(String str) {
    if (str.isEmpty()) {
      return str;
    }
    return reverse(str.substring(1)) + str.charAt(0);
  }
}
