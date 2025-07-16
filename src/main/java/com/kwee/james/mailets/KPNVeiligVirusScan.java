package com.kwee.james.mailets;

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

import org.apache.mailet.Mail;
import org.apache.mailet.MailetException;
import org.apache.mailet.base.GenericMailet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KPNVeiligVirusScan extends GenericMailet {
  private static final Logger LOGGER = LoggerFactory.getLogger(KPNVeiligVirusScan.class);

  private Path tmpDir;
  private String kpnVeiligPath;
  private boolean quarantineEnabled;
  private Path quarantineDir;
  private int scanTimeout;

  /*
   * "C:\Program Files (x86)\KPN Veilig\fsscan.exe" "%FILE%" Returncode = 3 virus
   * found
   */
  @Override
  public void init() throws MailetException {
    // Configuratie parameters
    tmpDir = Paths.get(getInitParameter("tmpDir", "C:\\James\\temp"));
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

  @Override
  public void service(Mail mail) throws MessagingException {
    try {
      LOGGER.info("KPN Veilig service");
      // Sla mail tijdelijk op
      Path tempFile = Files.createTempFile(tmpDir, "scan-", ".eml");
      try (OutputStream out = Files.newOutputStream(tempFile)) {
        mail.getMessage().writeTo(out);
      }

      // Voer F-KPN Veilig scan uit
      boolean infected = scanFileWithKPNVScan(tempFile);

      if (infected) {
        LOGGER.debug("KPN Veilig output infected: " + tempFile.toString());
        handleInfected(mail, tempFile);
      } else {
        LOGGER.debug("KPN Veilig output: " + tempFile.toString());
        // Files.delete(tempFile);
      }
    } catch (IOException e) {
      throw new MessagingException("Scan failed", e);
    }
  }

  public boolean scanFileWithKPNVScan(Path file) throws IOException, MailetException {
    ProcessBuilder pb = new ProcessBuilder(kpnVeiligPath,
        // "/ARCHIVE", // Scan binnen archives
        // "/DELETE", // Verwijder geïnfecteerde bestanden
        // "/REPORT=XML", // XML-formaat voor parsing
        file.toString());
// "C:\Program Files (x86)\KPN Veilig\fsscan.exe" "%FILE%"
    LOGGER.debug("Commandline: " + pb.command().toString() + " " + fileExists(file));
    pb.redirectErrorStream(true);
    pb.inheritIO();
    try {
      Process process = pb.start();
      int procexit = process.waitFor();
      LOGGER.debug("Procexit result: " + procexit);
      // Wacht met timeout
      if (!process.waitFor(scanTimeout, TimeUnit.MILLISECONDS)) {
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

  private void handleInfected(Mail mail, Path file) throws MessagingException {
    // Stuur notificatie
    // Maak een nieuwe error mail
    // Gebruik de mailet context direct
    mail.setErrorMessage("The attached email contained a virus and was blocked.");
    getMailetContext().sendMail(mail);

    // Quarantaine indien geconfigureerd
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

    // Stop verdere verwerking
    mail.setState(Mail.GHOST);
  }

  @Override
  public String getMailetInfo() {
    return "KPN Veilig Antivirus Scanner Mailet (fsscan.exe)";
  }

  String fileExists(Path path) {
    if (Files.exists(path) && Files.isRegularFile(path)) {
      return "Het bestand bestaat en is een normaal bestand.";
    } else if (Files.exists(path) && Files.isDirectory(path)) {
      return "Het pad verwijst naar een directory, niet naar een bestand.";
    } else {
      return "Het bestand bestaat niet.";
    }
  }
}