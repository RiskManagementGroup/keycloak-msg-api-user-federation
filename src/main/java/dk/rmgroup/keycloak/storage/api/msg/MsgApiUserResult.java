package dk.rmgroup.keycloak.storage.api.msg;

import java.util.List;

import org.keycloak.storage.user.SynchronizationResult;

public class MsgApiUserResult {
  public final SynchronizationResult synchronizationResult;
  public final List<String> errors;

  public MsgApiUserResult(SynchronizationResult synchronizationResult, List<String> errors) {
    this.synchronizationResult = synchronizationResult;
    this.errors = errors;
  }
}
