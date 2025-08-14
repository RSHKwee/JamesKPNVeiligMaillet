package org.apache.james.mailets.Kwee;

/**
 * Package KPN Virus scan on Windows.
 */
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.apache.mailet.Attribute;
import org.apache.mailet.AttributeName;
import org.apache.mailet.AttributeValue;
import org.apache.mailet.Mail;
import org.apache.mailet.MailetException;
import org.apache.mailet.base.GenericMailet;
import org.apache.mailet.base.RFC2822Headers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KPNVeiligVirusScan extends GenericMailet {
  private static final Logger LOGGER = LoggerFactory.getLogger(KPNVeiligVirusScan.class);
  private static final String INFONAME = "KPN Veilig";

  protected static final AttributeName INFECTED_MAIL_ATTRIBUTE_NAME = AttributeName.of("org.apache.james.infected");
  protected static final String INFECTED_HEADER_NAME = "X-MessageIsInfected";
  protected static final String INFECTED_HEADER_NAME_STATUS = "X-Virus-Status";
  protected static final String INFECTED_HEADER_NAME_SCANNED = "X-Virus-Scanned";

  private Path tmpDir;
  private String kpnVeiligPath;
  private int scanTimeout;

  /**
   * Initialize configuration parameters
   * 
   * Additional info: "C:\Program Files (x86)\KPN Veilig\fsscan.exe" "%FILE%"
   * Returncode = 3 virus found
   * 
   * @throws MailetException
   */
  @Override
  public void init() throws MailetException {
    String os = System.getProperty("os.name").toLowerCase();

    if (!os.contains("win")) {
      throw new MailetException("Only Windows supported.");
    }
    Path tempPath = Paths.get(System.getProperty("java.io.tmpdir"));

    tmpDir = Paths.get(getInitParameter("tmpDir", tempPath.toAbsolutePath().toString()));
    kpnVeiligPath = getInitParameter("kpnVeiligPath", "C:\\Program Files (x86)\\KPN Veilig\\fsscan.exe");
    scanTimeout = Integer.parseInt(getInitParameter("scanTimeout", "30000"));

    LOGGER.debug("KPN Veilig service started.");
  }

  /**
   * Perform service
   * 
   * @param mail Mail to be scanned
   * @throws MessagingException
   */
  @Override
  public void service(Mail mail) throws MessagingException {
    try {
      LOGGER.debug("KPN Veilig service");
      // Store mail temporarily on disk
      Path tempFile = Files.createTempFile(tmpDir, "scan-", ".eml");
      try (OutputStream out = Files.newOutputStream(tempFile)) {
        mail.getMessage().writeTo(out);
      }

      // Perform scan
      boolean infected = scanFileWithKPNVScan(tempFile);
      if (infected) {
        LOGGER.info("KPN Veilig output infected: " + tempFile.toString());
        handleInfected(mail);

        if (!LOGGER.isDebugEnabled()) {
          try {
            Files.delete(tempFile);
          } catch (Exception e) {
            // Do nothing
          }
        }
      } else {
        Files.delete(tempFile);
      }
    } catch (IOException e) {
      throw new MessagingException("Scan failed", e);
    }
  }

  /**
   * Scan file for virus
   * 
   * @param file File to scan
   * @return false: No virus found, true A virus is found
   * @throws IOException     IO Exception
   * @throws MailetException Mailet exception
   */
  public boolean scanFileWithKPNVScan(Path file) throws IOException, MailetException {
    ProcessBuilder pb = new ProcessBuilder(kpnVeiligPath, file.toAbsolutePath().toString());

    pb.redirectErrorStream(true);
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Commandline: " + pb.command().toString() + " " + file.toAbsolutePath().toString());
      pb.inheritIO();
    }

    try {
      Process process = pb.start();
      int procexit = process.waitFor();

      // Wait with timeout
      if (!process.waitFor(scanTimeout, TimeUnit.MILLISECONDS)) {
        process.destroyForcibly();
        throw new MailetException(INFONAME + " scan timeout exceeded");
      }
      LOGGER.debug("Procexit result: " + procexit);

      // Parse exit code:
      // 0 = clean, 3 = infected, other codes = error
      int exitCode = process.exitValue();
      LOGGER.debug("Scan result: " + exitCode);

      if (exitCode > 1) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
          String line;
          while ((line = reader.readLine()) != null) {
            LOGGER.debug(INFONAME + " output: " + line);
          }
        }
      }
      return exitCode == 3;

    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new MailetException("Scan interrupted", e);
    }
  }

  /**
   * Give mailet information.
   */
  @Override
  public String getMailetInfo() {
    return INFONAME + " Antivirus Scanner Mailet (fsscan.exe)";
  }

  // v ========== Private functions ================
  /**
   * Handle a mail with a virus. By sending a notification, create a new mai with
   * use of the mailet context.
   *
   * @param mail Mail with virus
   * @throws MessagingException Message exception
   */
  private void handleInfected(Mail mail) throws MessagingException {
    mail.setErrorMessage("The attached email contained a virus and was blocked.");
    // mail.setState(Mail.GHOST);
    try {
      removeAttachments(mail);
    } catch (IOException e) {
      LOGGER.info("handleInfected mail goes wrong: " + e.getMessage());
    }

    // mark the mail with a mail attribute to check later on by other
    // matchers/mailets
    mail.setAttribute(makeInfectedAttribute(true));
    MimeMessage mimeMessage = mail.getMessage();

    // mark the message with a header string
    mimeMessage.setHeader(INFECTED_HEADER_NAME, "true");
    mimeMessage.addHeader(INFECTED_HEADER_NAME_STATUS, "Infected");
    mimeMessage.addHeader(INFECTED_HEADER_NAME_SCANNED, INFONAME);

    mimeMessage.saveChanges();

    getMailetContext().sendMail(mail);
  }

  private Attribute makeInfectedAttribute(boolean value) {
    return new Attribute(INFECTED_MAIL_ATTRIBUTE_NAME, AttributeValue.of(value));
  }

  /**
   * Remove (infected) attachments
   * 
   * @param mail
   * @throws MessagingException
   * @throws IOException
   */
  private void removeAttachments(Mail mail) throws MessagingException, IOException {
    MimeMessage mimeMessage = mail.getMessage();
    int removedCount = 0;
    StringBuilder removedFiles = new StringBuilder();

    if (mimeMessage.isMimeType("multipart/*")) {
      MimeMultipart originalMultipart = (MimeMultipart) mimeMessage.getContent();
      MimeMultipart newMultipart = new MimeMultipart();

      for (int i = 0; i < originalMultipart.getCount(); i++) {
        MimeBodyPart part = (MimeBodyPart) originalMultipart.getBodyPart(i);

        if (part.getDisposition() != null && part.getDisposition().equalsIgnoreCase(Part.ATTACHMENT)) {
          removedCount++;
          removedFiles.append("\n- ").append(part.getFileName());
        } else {
          newMultipart.addBodyPart(part);
        }
      }

      if (removedCount > 0) {
        addRemovalNotice(newMultipart, removedCount, removedFiles.toString());
      }

      mimeMessage.setContent(newMultipart);
      mimeMessage.saveChanges();
    }
  }

  /**
   * Strip mail from attachment(s) and make announcement...
   * 
   * @param multipart
   * @param removedCount
   * @param fileNames
   * @throws MessagingException
   */
  private void addRemovalNotice(MimeMultipart multipart, int removedCount, String fileNames) throws MessagingException {
    // Create new body part with a remark
    MimeBodyPart noticePart = new MimeBodyPart();

    String noticeText = String.format(
        "\n\n---\n" + "Opmerking: %d bijlage(n) is/zijn verwijderd uit dit bericht:%s\n" + "---\n", removedCount,
        fileNames);

    // Add remark to existing text
    try {
      // Haal de bestaande tekst/html body part op
      for (int i = 0; i < multipart.getCount(); i++) {
        MimeBodyPart part = (MimeBodyPart) multipart.getBodyPart(i);
        if (part.isMimeType("text/plain")) {
          String currentContent = (String) part.getContent();
          part.setText(currentContent + noticeText);
          return;
        } else if (part.isMimeType("text/html")) {
          String currentContent = (String) part.getContent();
          String htmlNotice = String.format(
              "<hr><p><em>Opmerking: %d bijlage(n) is/zijn verwijderd uit dit bericht:%s</em></p>", removedCount,
              fileNames.replace("\n", "<br>"));
          part.setContent(currentContent + htmlNotice, "text/html");
          return;
        }
      }

      // If no text part found, then create a new one.
      noticePart.setText(noticeText);
      multipart.addBodyPart(noticePart);

    } catch (IOException e) {
      throw new MessagingException("Kon content niet lezen", e);
    }
  }

  /**
   * Saves changes resetting the original message id.
   *
   * @param message the message to save
   */
  protected final void saveChanges(MimeMessage message) throws MessagingException {
    String messageId = message.getMessageID();
    message.saveChanges();
    if (messageId != null) {
      message.setHeader(RFC2822Headers.MESSAGE_ID, messageId);
    }
  }
}