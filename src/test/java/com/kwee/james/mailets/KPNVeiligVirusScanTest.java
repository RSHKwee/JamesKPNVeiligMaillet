package com.kwee.james.mailets;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;

import org.apache.james.core.builder.MimeMessageBuilder;
import org.apache.mailet.Mail;
import org.apache.mailet.MailetContext;
import org.apache.mailet.base.test.FakeMail;
import org.apache.mailet.base.test.FakeMailetConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import jakarta.mail.MessagingException;

public class KPNVeiligVirusScanTest {
  private static final Logger LOGGER = LoggerFactory.getLogger(KPNVeiligVirusScanTest.class);

  private KPNVeiligVirusScan mailet;
  private MailetContext mailetContext;
  private FakeMailetConfig mailetConfig;

  @BeforeMethod
  public void setUp() throws Exception {
    mailet = new KPNVeiligVirusScan();
    mailetContext = mock(MailetContext.class);
    //@formatter:off
    mailetConfig = FakeMailetConfig.builder()
        .mailetName("KPNVeiligScan")
        .mailetContext(mailetContext)
        .setProperty("kpnVeiligPath", "C:\\Program Files (x86)\\KPN Veilig\\fsscan.exe")
        .setProperty("tmpDir", "target\\tmp")
        .setProperty("quarantineDir", "target/quarantine")
        .build();
    //@formatter:on
  }

  @Test
  public void testInitShouldCreateDirectories() throws Exception {
    LOGGER.info("testInitShouldCreateDirectories");
    mailet.init(mailetConfig);
    // Hier zou je kunnen verifiëren of directories zijn aangemaakt
    // (In echte implementatie zou je Files.exists checken)
  }

  @Test
  public void testCleanMailShouldContinueProcessing() throws Exception {
    LOGGER.info("testCleanMailShouldContinueProcessing");
    // Arrange
    mailet.init(mailetConfig);
    Mail mail = createTestMail();

    // Mock de scanner om false (schoon) terug te geven
    KPNVeiligVirusScan spyMailet = spy(mailet);
    spyMailet.service(mail);

    // Assert
    assertNull(mail.getState(), "Mail state should not be changed");
  }

  @Test
  public void testInfectedMailShouldBeQuarantined() throws Exception {
    LOGGER.info("testInfectedMailShouldBeQuarantined");
    // Arrange
    mailet.init(mailetConfig);
    Mail mail = createInfectedMail();

    // Mock de scanner om true (geïnfecteerd) terug te geven
    KPNVeiligVirusScan spyMailet = spy(mailet);
//  doReturn(true).when(spyMailet).scanFileWithKPNVScan(any());

    // Act
    spyMailet.service(mail);

    // Assert
    assertEquals(mail.getState(), Mail.GHOST, "Mail should be ghosted");
  }

  @Test(expectedExceptions = MessagingException.class)
  public void testScanFailureShouldThrowException() throws Exception {
    LOGGER.info("testScanFailureShouldThrowException");
    // Arrange
    mailet.init(mailetConfig);
    Mail mail = createTestMail();

    // Mock de scanner om een exception te gooien
    KPNVeiligVirusScan spyMailet = spy(mailet);
    doThrow(new MessagingException("Scan error")).when(spyMailet).scanFileWithKPNVScan(any());

    // Act
    spyMailet.service(mail);
  }

  @Test
  public void testQuarantineDisabled() throws Exception {
    LOGGER.info("testQuarantineDisabled");
    // Arrange
    mailetConfig = FakeMailetConfig.builder().mailetName("KPNVeiligVirusScan").mailetContext(mailetContext)
        .setProperty("quarantine", "false").setProperty("tmpDir", "target\\tmp").build();
    mailet.init(mailetConfig);

    Mail mail = createInfectedMail();
    KPNVeiligVirusScan spyMailet = spy(mailet);

    // Act
    spyMailet.service(mail);

    // Assert
    assertEquals(mail.getState(), Mail.GHOST, "Mail should be ghosted");
    // Verify no move to quarantine happened
    // (In echte implementatie zou je filesystem checks doen)
  }

// Local routines
//
  private Mail createTestMail() {
    javax.mail.internet.MimeMessage message;
    try {
      message = MimeMessageBuilder.mimeMessageBuilder().setSubject("Test mail").setText("Hello world!").build();
      return FakeMail.builder().name("mail1").mimeMessage(message).sender("sender@domain.com")
          .recipient("recipient@domain.com").build();
    } catch (Exception e) {
      // TODO Auto-generated catch block
      LOGGER.info(e.getMessage().toString());
      // e.printStackTrace();
    }
    return null;
  }

  // " *H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
  private Mail createInfectedMail() throws MessagingException, IOException {
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

      mail = FakeMail.builder().name("virus-test-mail").mimeMessage(mimeMessage).sender("sender@domain.com")
          .recipient("recipient@domain.com").build();

      return mail;
    } catch (Exception e) {
      // TODO Auto-generated catch block
      // e.printStackTrace();
      LOGGER.info(e.getMessage().toString());
    }
    return null;
  }

  @Test
  public void testKPNcall() throws Exception {
    mailet.init(mailetConfig);
    LOGGER.info("testKPNcall");

    Path zipPath = Paths.get("resources\\eicar_com.zip");
    FileSystem zipFs1 = FileSystems.newFileSystem(zipPath, (ClassLoader) null);
    // Create a filesystem for the ZIP file
    try (FileSystem zipFs = FileSystems.newFileSystem(zipPath, (ClassLoader) null)) {
      // Get path to entry inside the ZIP
      Path entryPath = zipFs.getPath("eicar.com");
      // Path entryPath = zipFs.getPath("F:\\dev\\James
      // Mailets\\KPNVeiligMailet\\target\\tmp\\eicar.com");

      // File testfile = new File("target/tmp/ecar.eml");
      // Path pad = testfile.toPath();
      LOGGER.debug("File:  " + entryPath.toAbsolutePath().toString());

      KPNVeiligVirusScan spyMailet = spy(mailet);

      boolean result = spyMailet.scanFileWithKPNVScan(entryPath);
      LOGGER.info("Result: " + result);
    }

  }

  private String reverse(String str) {
    if (str.isEmpty()) {
      return str;
    }
    return reverse(str.substring(1)) + str.charAt(0);
  }

}