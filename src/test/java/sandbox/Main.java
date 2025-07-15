package sandbox;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.core.util.StatusPrinter;

public class Main {
  private static final Logger logger = (Logger) LoggerFactory.getLogger(Main.class);

  public static void main(String[] args) {
    // Print Logback's interne status
    ch.qos.logback.classic.LoggerContext loggerContext = (ch.qos.logback.classic.LoggerContext) LoggerFactory
        .getILoggerFactory();
    StatusPrinter.print(loggerContext);

    Logger rootLogger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    rootLogger.setLevel(Level.TRACE);

    // System.setProperty("org.slf4j.Logger.defaultLogLevel", "TRACE");
    logger.setLevel(Level.TRACE);
    // Optioneel: debug interne SLF4J-initialisatie
    // System.setProperty("org.slf4j.Logger", "DEBUG");

    logger.info("Dit wordt naar de console gelogd! info");
    logger.error("Dit wordt naar de console gelogd! error");
    logger.debug("Dit wordt naar de console gelogd! debug");
    logger.warn("Dit wordt naar de console gelogd! warn");
    logger.trace("Dit wordt naar de console gelogd! trace");
  }
}
