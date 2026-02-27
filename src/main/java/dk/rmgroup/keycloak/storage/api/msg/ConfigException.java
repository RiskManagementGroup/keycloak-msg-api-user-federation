package dk.rmgroup.keycloak.storage.api.msg;

public class ConfigException extends RuntimeException {
  public ConfigException(String message) {
    super(message);
  }

  public ConfigException(String message, Throwable cause) {
    super(message, cause);
  }
}