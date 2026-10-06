package dk.rmgroup.keycloak.storage.api.msg;

import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.cluster.ClusterEvent;
import org.keycloak.cluster.ClusterListener;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.StorageProviderRealmModel;
import static org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.provider.ProviderEventListener;
import org.keycloak.storage.StoreSyncEvent;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderClusterEvent;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.UserStorageProviderModel.SyncMode;

public class MsgApiUserStorageEventListener implements ClusterListener, ProviderEventListener {

  private final KeycloakSessionFactory sessionFactory;

  private static final String MSG_API_USER_STORAGE_TASK_KEY = "msg-api-user-storage";

  private static final Logger logger = Logger.getLogger(MsgApiUserStorageEventListener.class);

  private static final String MSG_API_PROVIDER_ID = "msg";

  public MsgApiUserStorageEventListener(KeycloakSessionFactory sessionFactory) {
    this.sessionFactory = sessionFactory;
  }

  @Override
  public void eventReceived(ClusterEvent event) {
    UserStorageProviderClusterEvent fedEvent = (UserStorageProviderClusterEvent) event;
    String realmId = fedEvent.getRealmId();

    runJobInTransaction(sessionFactory, session -> {
      RealmModel realm = session.realms().getRealm(realmId);

      if (realm == null) {
        if (fedEvent.isRemoved()) {
          logger.debugf(
              "Realm with id %s not found when handling user storage removal event, it may have been deleted already",
              realmId);
          return;
        }
        throw new RuntimeException("Failed to execute session task. Realm with id " + realmId + " not found.");
      }

      session.getContext().setRealm(realm);
      if (fedEvent.getStorageProvider().getProviderId().equals(MSG_API_PROVIDER_ID)) {
        refreshScheduledTasks(session, fedEvent.getStorageProvider(), fedEvent.isRemoved());
      }
    });
  }

  @Override
  public void onEvent(ProviderEvent event) {
    if (event instanceof PostMigrationEvent) {
      runJobInTransaction(sessionFactory, session -> {
        session.realms().getRealmsWithProviderTypeStream(UserStorageProvider.class)
            .forEach(realm -> {
              if (realm.getComponentsStream().anyMatch(p -> MSG_API_PROVIDER_ID.equals(p.getProviderId()))) {
                try {
                  session.getContext().setRealm(realm);
                  getUserStorageProvidersStream(realm).filter(p -> p.getProviderId().equals(MSG_API_PROVIDER_ID))
                      .forEachOrdered(provider -> reScheduleTasks(session, provider));
                } finally {
                  session.getContext().setRealm(null);
                }
              }
            });

        ClusterProvider clusterProvider = session.getProvider(ClusterProvider.class);

        if (clusterProvider != null) {
          clusterProvider.registerListener(MSG_API_USER_STORAGE_TASK_KEY, this);
        }
      });
    } else if (event instanceof StoreSyncEvent ev) {
      UserStorageProviderModel model = ev.getModel() == null ? null : new UserStorageProviderModel(ev.getModel());
      boolean removed = ev.getRemoved();
      String realmId = ev.getRealm().getId();

      runJobInTransaction(sessionFactory, session -> {
        RealmModel realm = session.realms().getRealm(realmId);
        if (realm == null) {
          return;
        }

        session.getContext().setRealm(realm);

        if (model != null) {
          if (MSG_API_PROVIDER_ID.equals(model.getProviderId())) {
            refreshScheduledTasks(session, model, removed);
            notifyStoreSyncClusterUpdate(session, realm, model, removed);
          }
        } else {
          getUserStorageProvidersStream(realm).forEachOrdered(fedProvider -> {
            if (MSG_API_PROVIDER_ID.equals(fedProvider.getProviderId())) {
              refreshScheduledTasks(session, fedProvider, removed);
              notifyStoreSyncClusterUpdate(session, realm, fedProvider, removed);
            }
          });
        }
      });
    }
  }

  public void scheduleTask(KeycloakSession session, UserStorageProviderModel provider, SyncMode mode) {
    MsgApiUserStorageSyncTask task = new MsgApiUserStorageSyncTask(provider, mode);

    if (!task.schedule(session)) {
      // cancel potentially dangling task
      task.cancel(session);
    }
  }

  private Stream<UserStorageProviderModel> getUserStorageProvidersStream(RealmModel realm) {
    if (realm instanceof StorageProviderRealmModel s) {
      return s.getUserStorageProvidersStream();
    }

    return Stream.empty();
  }

  private void reScheduleTasks(KeycloakSession session, UserStorageProviderModel provider) {
    KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
    UserStorageProviderFactory<?> factory = (UserStorageProviderFactory<?>) sessionFactory
        .getProviderFactory(UserStorageProvider.class, provider.getProviderId());
    RealmModel realm = session.getContext().getRealm();

    if (!(factory instanceof MsgApiUserStorageProviderFactory)) {
      logger.debugf("Not refreshing periodic sync settings for provider '%s' in realm '%s'", provider.getName(),
          realm.getName());
      return;
    }

    logger.debugf(
        "Going to refresh periodic sync settings for provider '%s' in realm '%s' with realmId '%s'. Full sync period: %d , changed users sync period: %d",
        provider.getName(), realm.getName(), realm.getId(), provider.getFullSyncPeriod(),
        provider.getChangedSyncPeriod());
    scheduleTask(session, provider, SyncMode.FULL);
    scheduleTask(session, provider, SyncMode.CHANGED);
  }

  // Ensure all cluster nodes are notified
  private void notifyStoreSyncClusterUpdate(KeycloakSession session, RealmModel realm,
      UserStorageProviderModel provider, boolean removed) {
    KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
    UserStorageProviderFactory<?> factory = (UserStorageProviderFactory<?>) sessionFactory
        .getProviderFactory(UserStorageProvider.class, provider.getProviderId());

    if (!(factory instanceof MsgApiUserStorageProviderFactory)) {
      return;
    }

    ClusterProvider cp = session.getProvider(ClusterProvider.class);

    if (cp != null) {
      UserStorageProviderClusterEvent event = UserStorageProviderClusterEvent.createEvent(removed, realm.getId(),
          provider);
      cp.notify(MSG_API_USER_STORAGE_TASK_KEY, event, true);
    }
  }

  private void refreshScheduledTasks(KeycloakSession session, UserStorageProviderModel model, boolean removed) {
    if (removed) {
      new MsgApiUserStorageSyncTask(model, SyncMode.FULL).cancel(session);
      new MsgApiUserStorageSyncTask(model, SyncMode.CHANGED).cancel(session);
    } else {
      reScheduleTasks(session, model);
    }
  }
}
