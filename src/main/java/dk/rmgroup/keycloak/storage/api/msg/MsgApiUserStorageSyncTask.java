package dk.rmgroup.keycloak.storage.api.msg;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import org.jboss.logging.Logger;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.cluster.ExecutionResult;
import org.keycloak.common.util.Time;
import org.keycloak.common.util.TriFunction;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ModelIllegalStateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.UserStorageProviderModel.SyncMode;
import org.keycloak.storage.user.SynchronizationResult;
import org.keycloak.timer.ScheduledTask;
import org.keycloak.timer.TimerProvider;
import org.keycloak.timer.TimerProvider.TimerTaskContext;
import org.springframework.scheduling.support.CronExpression;

import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_ENABLE_FULL_SYNC_WITH_SPECIFIC_TIME;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_FULL_SYNC_SPECIFIC_TIME;

public class MsgApiUserStorageSyncTask implements ScheduledTask {

  private static final Logger logger = Logger.getLogger(MsgApiUserStorageSyncTask.class);
  private static final int TASK_EXECUTION_TIMEOUT = 30;
  private static final String MSG_API_PROVIDER_ID = "msg";

  private final String providerId;
  private final String realmId;
  private final SyncMode syncMode;

  MsgApiUserStorageSyncTask(UserStorageProviderModel provider, SyncMode syncMode) {
    this.providerId = provider.getId();
    this.realmId = provider.getParentId();
    this.syncMode = syncMode;
  }

  @Override
  public void run(KeycloakSession session) {
    ClusterProvider clusterProvider = session.getProvider(ClusterProvider.class);
    if (clusterProvider.isPrimaryClusterSupported() && !clusterProvider.isPrimaryCluster()) {
      return;
    }

    RealmModel realm = session.realms().getRealm(realmId);

    session.getContext().setRealm(realm);

    runWithResult(session);
  }

  @Override
  public String getTaskName() {
    return MsgApiUserStorageSyncTask.class.getSimpleName() + "-" + providerId + "-" + syncMode;
  }

  SynchronizationResult runWithResult(KeycloakSession session) {
    try {
      return switch (syncMode) {
        case FULL ->
          runFullSync(session);
        case CHANGED ->
          runIncrementalSync(session);
      };
    } catch (Throwable t) {
      logger.errorf(t, "Error occurred during %s users-sync in realm %s and user provider %s", syncMode, realmId,
          providerId);
    }

    return SynchronizationResult.empty();
  }

  boolean schedule(KeycloakSession session) {
    UserStorageProviderModel provider = getStorageModel(session);

    if (isSchedulable(provider) && MSG_API_PROVIDER_ID.equals(provider.getProviderId())) {
      TimerProvider timer = session.getProvider(TimerProvider.class);

      if (timer == null) {
        logger.debugf(
            "Timer provider not available. Not scheduling periodic sync task for provider '%s' in realm '%s'",
            provider.getName(), realmId);
        return false;
      }

      logger.debugf(
          "Scheduling user periodic sync task '%s' for user storage provider '%s' in realm '%s'",
          getTaskName(), provider.getName(), realmId);
      CronExpression cronExpression = CronExpression.parse(provider.get(CONFIG_KEY_FULL_SYNC_SPECIFIC_TIME));
      LocalDateTime nextExecution = cronExpression.next(LocalDateTime.now(ZoneId.of("Europe/Copenhagen")));
      ZonedDateTime zonedNextExecution = nextExecution.atZone(ZoneId.of("Europe/Copenhagen"));
      timer.scheduleTask(this, getTimeTo(zonedNextExecution.toInstant().toEpochMilli()));

      return true;
    }

    logger.debugf("Not scheduling periodic sync settings for provider '%s' in realm '%s'", provider.getName(),
        realmId);

    return false;
  }

  long getTimeTo(long toMili) {
    return toMili - System.currentTimeMillis();
  }

  void cancel(KeycloakSession session) {
    TimerProvider timer = session.getProvider(TimerProvider.class);

    if (timer == null) {
      logger.debugf(
          "Timer provider not available. Not cancelling periodic sync task for provider id '%s' in realm '%s'",
          providerId, realmId);
      return;
    }

    logger.debugf(
        "Cancelling any running user periodic sync task '%s' for user storage provider provider '%s' in realm '%s'",
        getTaskName(), providerId, realmId);

    TimerTaskContext existingTask = timer.cancelTask(getTaskName());

    if (existingTask != null) {
      logger.debugf("Cancelled periodic sync task with task-name '%s' for provider with id '%s'",
          getTaskName(), providerId);
    }
  }

  private UserStorageProviderModel getStorageModel(KeycloakSession session) {
    RealmModel realm = session.getContext().getRealm();

    if (realm == null) {
      throw new ModelIllegalStateException("Realm with id " + realmId + " not found");
    }

    ComponentModel component = realm.getComponent(providerId);

    if (component == null) {
      cancel(session);
      throw new ModelIllegalStateException(
          "User storage provider with id " + providerId + " not found in realm " + realm.getName());
    }

    return new UserStorageProviderModel(component);
  }

  private SynchronizationResult runFullSync(KeycloakSession session) {
    return runSync(session,
        (sf, storage, model) -> storage.sync(sf, realmId, model));
  }

  private SynchronizationResult runIncrementalSync(KeycloakSession session) {
    return runSync(session, (sf, storage, model) -> {
      // See when we did last sync.
      int oldLastSync = model.getLastSync();
      return storage.syncSince(Time.toDate(oldLastSync), sf, realmId, model);
    });
  }

  private SynchronizationResult runSync(KeycloakSession session,
      TriFunction<KeycloakSessionFactory, MsgApiUserStorageProviderFactory, UserStorageProviderModel, SynchronizationResult> syncFunction) {
    UserStorageProviderModel provider = getStorageModel(session);
    KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
    MsgApiUserStorageProviderFactory factory = getProviderFactory(session, provider);

    if (factory == null) {
      logger.warnf("Provider factory for provider with id '%s' is not an instance of MsgApiUserStorageProviderFactory",
          provider.getId());
      return SynchronizationResult.ignored();
    }

    ClusterProvider clusterProvider = session.getProvider(ClusterProvider.class);
    // shared key for "full" and "changed" . Improve if needed
    String taskKey = provider.getId() + "::sync";
    // 30 seconds minimal timeout for now
    int timeout = Math.max(TASK_EXECUTION_TIMEOUT, 24 * 60 * 60);

    ExecutionResult<SynchronizationResult> task = clusterProvider.executeIfNotExecuted(taskKey, timeout, () -> {
      // Need to load component again in this transaction for updated data
      SynchronizationResult result = syncFunction.apply(sessionFactory, factory, provider);

      if (!result.isIgnored()) {
        KeycloakModelUtils.runJobInTransaction(sessionFactory, s -> {
          RealmModel realm = s.realms().getRealm(realmId);
          s.getContext().setRealm(realm);
          updateLastSyncInterval(s);
        });
      }

      return result;
    });

    SynchronizationResult result = task.getResult();

    if (result == null || !task.isExecuted()) {
      logger.debugf("syncing users for federation provider %s was ignored as it's already in progress",
          provider.getName());
      return SynchronizationResult.ignored();
    }

    this.schedule(session);

    return result;
  }

  private MsgApiUserStorageProviderFactory getProviderFactory(KeycloakSession session,
      UserStorageProviderModel provider) {
    KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
    UserStorageProviderFactory<?> factory = (UserStorageProviderFactory<?>) sessionFactory
        .getProviderFactory(UserStorageProvider.class, provider.getProviderId());

    if (factory instanceof MsgApiUserStorageProviderFactory f) {
      return f;
    }

    return null;
  }

  // Update interval of last sync for given UserFederationProviderModel. Do it in
  // separate transaction
  private void updateLastSyncInterval(KeycloakSession session) {
    UserStorageProviderModel provider = getStorageModel(session);

    // Update persistent provider in DB
    provider.setLastSync(Time.currentTime(), syncMode);

    RealmModel realm = session.getContext().getRealm();

    realm.updateComponent(provider);
  }

  private boolean isSchedulable(UserStorageProviderModel provider) {
    return provider.isEnabled() && provider.get(CONFIG_KEY_ENABLE_FULL_SYNC_WITH_SPECIFIC_TIME, false);
  }
}
