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
import java.nio.file.StandardCopyOption;
import java.util.concurrent.TimeUnit;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

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
  protected static final AttributeName INFECTED_MAIL_ATTRIBUTE_NAME = AttributeName.of("org.apache.james.infected");
  protected static final String INFECTED_HEADER_NAME = "X-MessageIsInfected";

  private Path tmpDir;
  private String kpnVeiligPath;
  private boolean quarantineEnabled;
  private Path quarantineDir;
  private int scanTimeout;

  /**
   * Initialize configuration parameters Additional info: "C:\Program Files
   * (x86)\KPN Veilig\fsscan.exe" "%FILE%" Returncode = 3 virus found
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
    quarantineEnabled = Boolean.parseBoolean(getInitParameter("quarantine", "true"));
    quarantineDir = Paths.get(getInitParameter("quarantineDir", "C:\\James\\quarantine"));
    scanTimeout = Integer.parseInt(getInitParameter("scanTimeout", "30000"));

    try {
      Files.createDirectories(tmpDir);
      if (quarantineEnabled) {
        Files.createDirectories(quarantineDir);
      }
    } catch (IOException e) {
      throw new MailetException("Could not create directories", e);
    }
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
      LOGGER.info("KPN Veilig service");
      // Sla mail tijdelijk op
      Path tempFile = Files.createTempFile(tmpDir, "scan-", ".eml");
      try (OutputStream out = Files.newOutputStream(tempFile)) {
        mail.getMessage().writeTo(out);
      }

      // Perform scan
      boolean infected = scanFileWithKPNVScan(tempFile);

      if (infected) {
        LOGGER.info("KPN Veilig output infected: " + tempFile.toString());
        handleInfected(mail, tempFile);

        // mark the mail with a mail attribute to check later on by other
        // matchers/mailets
        mail.setAttribute(makeInfectedAttribute(true));
        MimeMessage mimeMessage = mail.getMessage();

        // mark the message with a header string
        mimeMessage.setHeader(INFECTED_HEADER_NAME, "true");

      } else {
        LOGGER.debug("KPN Veilig output: " + tempFile.toString());
        if (!LOGGER.isDebugEnabled()) {
          Files.delete(tempFile);
        }
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
        throw new MailetException("KPN Veilig scan timeout exceeded");
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
            LOGGER.debug("KPN Veilig output: " + line);
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
   * Handle a mail with a virus. By sending a notification, create a new mai with
   * use of the mailet context.
   *
   * @param mail Mail with virus
   * @param file Temporary copy of mail on disk.
   * @throws MessagingException Message exception
   */
  private void handleInfected(Mail mail, Path file) throws MessagingException {
    mail.setErrorMessage("The attached email contained a virus and was blocked.");
    mail.setState(Mail.GHOST);

    getMailetContext().sendMail(mail);

    // Quarantaine when configured
    if (quarantineEnabled) {
      try {
        String quarantineFileName = "infected-" + System.currentTimeMillis() + ".eml";
        Path target = quarantineDir.resolve(quarantineFileName);
        Files.move(file, target, StandardCopyOption.REPLACE_EXISTING);
        LOGGER.warn("Quarantined infected email to: " + target);
      } catch (IOException e) {
        throw new MessagingException("Quarantine failed", e);
      }
    }
  }

  /**
   * Give mailet information.
   */
  @Override
  public String getMailetInfo() {
    return "KPN Veilig Antivirus Scanner Mailet (fsscan.exe)";
  }

  private Attribute makeInfectedAttribute(boolean value) {
    return new Attribute(INFECTED_MAIL_ATTRIBUTE_NAME, AttributeValue.of(value));
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