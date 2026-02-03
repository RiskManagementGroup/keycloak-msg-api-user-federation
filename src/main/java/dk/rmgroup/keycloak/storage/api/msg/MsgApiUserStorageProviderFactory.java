package dk.rmgroup.keycloak.storage.api.msg;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.jboss.logging.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.StoreSyncEvent;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.user.ImportSynchronization;
import org.keycloak.storage.user.SynchronizationResult;

import com.google.common.base.Strings;
import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;

import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_DEFAULT_AUTHORITY;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_DEFAULT_MSG_URL;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_DEFAULT_SCOPE;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_ALLOW_UPDATE_UPN_DOMAINS;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_AUTHORITY;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_CLIENT_ID;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_DO_NOT_OVERRIDE_MOBILE_WITH_EMPTY;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_GROUPS_FOR_USERS_NOT_IN_MAPPED_GROUPS;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_GROUP_MAP;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_IMPORT_USERS_NOT_IN_MAPPED_GROUPS;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_MSG_BASE_URL;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_SCOPE;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_SECRET;

public class MsgApiUserStorageProviderFactory
    implements UserStorageProviderFactory<MsgApiUserStorageProvider>, ImportSynchronization {

  protected final List<ProviderConfigProperty> configMetadata;

  private static final Logger logger = Logger.getLogger(MsgApiUserStorageProviderFactory.class);

  private static final int USER_REMOVE_PAGE_SIZE = 100;

  private static final int USER_IMPORT_PAGE_SIZE = 100;

  public MsgApiUserStorageProviderFactory() {
    configMetadata = ProviderConfigurationBuilder.create()
        .property()
        .name(CONFIG_KEY_AUTHORITY)
        .label("Authority")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "The STS endpoint for user to authenticate. Usually https://login.microsoftonline.com/{tenant} for public cloud, where {tenant} is the name of your tenant or your tenant Id.")
        .defaultValue(CONFIG_DEFAULT_AUTHORITY)
        .add()
        .property()
        .name(CONFIG_KEY_CLIENT_ID)
        .label("Client ID")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "Is the Application (client) ID for the application registered in the Azure portal. You can find this value in the app's Overview page in the Azure portal.")
        .add()
        .property()
        .name(CONFIG_KEY_SECRET)
        .label("Secret")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("Is the client secret created for the application in Azure portal.")
        .add()
        .property()
        .name(CONFIG_KEY_SCOPE)
        .label("Scope")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "With client credentials flows the scope is ALWAYS of the shape \"resource/.default\", as the application permissions need to be set statically (in the portal), and then granted by a tenant administrator. Don't change this setting unless you know what you are doing.")
        .defaultValue(CONFIG_DEFAULT_SCOPE)
        .add()
        .property()
        .name(CONFIG_KEY_MSG_BASE_URL)
        .label("Microsoft Graph API Base Url")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("Base URL of the Microsoft Graph API endpoints.")
        .defaultValue(CONFIG_DEFAULT_MSG_URL)
        .add()
        .property()
        .name(CONFIG_KEY_ALLOW_UPDATE_UPN_DOMAINS)
        .label("Allow taking over users from UPN domains")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "Allow taking over federation for users whose UPN is one of the domains in this comma separated list. Note that this may overwrite data on existing users in the database!")
        .add()
        .property()
        .name(CONFIG_KEY_GROUP_MAP)
        .label("Group map")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "Specify the group map using a json object like this: {\"MSG Group 1\": \"/Keycoak Group 1\", \"MSG Group 2\": \"/Keycoak Group 2\"}, remember that group names are case sensitive!")
        .add()
        .property()
        .name(CONFIG_KEY_IMPORT_USERS_NOT_IN_MAPPED_GROUPS)
        .label("Import users not in mapped groups")
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .helpText(
            "Turn this ON if you would like to also import users that are not members of any of the mapped groups.")
        .add()
        .property()
        .name(CONFIG_KEY_GROUPS_FOR_USERS_NOT_IN_MAPPED_GROUPS)
        .label("Groups for users not in mapped groups")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "Comma separated list of Keycloak groups to be assigned to users who are not members of any of the mapped groups.")
        .add()
        .property()
        .name(CONFIG_KEY_DO_NOT_OVERRIDE_MOBILE_WITH_EMPTY)
        .label("Do not override mobile numbers with empty value")
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .helpText("If enabled, the mobile phone number will not be overridden if the new value is empty.")
        .add()
        .build();
  }

  @Override
  public String getId() {
    return "msg";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configMetadata;
  }

  @Override
  public MsgApiUserStorageProvider create(KeycloakSession ksession, ComponentModel model) {
    return new MsgApiUserStorageProvider();
  }

  @Override
  public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId,
      UserStorageProviderModel model) {
    return syncImpl(sessionFactory, realmId, model);
  }

  @Override
  public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory, String realmId,
      UserStorageProviderModel model) {
    return syncImpl(sessionFactory, realmId, model);
  }

  @Override
  public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config)
      throws ComponentValidationException {
    if (!config.contains(CONFIG_KEY_AUTHORITY)) {
      throw new ComponentValidationException("Authority is required!");
    }
    if (!config.contains(CONFIG_KEY_CLIENT_ID)) {
      throw new ComponentValidationException("Client ID is required!");
    }
    if (!config.contains(CONFIG_KEY_SECRET)) {
      throw new ComponentValidationException("Secret is required!");
    }
    if (!config.contains(CONFIG_KEY_SCOPE)) {
      throw new ComponentValidationException("Scope is required!");
    }
    if (!config.contains(CONFIG_KEY_MSG_BASE_URL)) {
      throw new ComponentValidationException("Microsoft Graph API Base Url is required!");
    }

    GroupMapConfig groupMapConfig = GetGroupMapConfig(session, realm, config);

    if (!groupMapConfig.errors.isEmpty()) {
      throw new ComponentValidationException(
          String.format("Errors found in Group map: %s", String.join(", ", groupMapConfig.errors)));
    }

    if (groupMapConfig.groupMap.isEmpty() && !config.get(CONFIG_KEY_IMPORT_USERS_NOT_IN_MAPPED_GROUPS, false)) {
      throw new ComponentValidationException(
          "You must turn ON \"Import users not in mapped groups\", when Group map is not specified!");
    }

    if (config.contains(CONFIG_KEY_GROUPS_FOR_USERS_NOT_IN_MAPPED_GROUPS)
        && !config.get(CONFIG_KEY_IMPORT_USERS_NOT_IN_MAPPED_GROUPS, false)) {
      throw new ComponentValidationException(
          "\"Groups for users not in mapped groups\" is not applicable, when \"Import users not in mapped groups\" is turned OFF!");
    }

    // For some reason enabled is set to 't' when saving configuration.
    // This will cause provider and linked users to get disabled and subsequent
    // periodic syncs not to run,
    // so we work around that by setting enabled to "true" in the
    // validateConfiguration.
    // This was not necessary prior to version 21
    String enabled = config.getConfig().getFirst("enabled");

    if ("t".equals(enabled)) {
      logger.debug("enabled is set to 't'. Will change it to 'true' as a workaround");
      config.getConfig().put("enabled", Arrays.asList("true"));
    }
  }

  @Override
  public void onUpdate(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
    // Periodic sync is normally only refreshed if there are changes to sync
    // intervals.
    // This means that other changes to the config is not applied to the periodic
    // sync,
    // until a restart or a change to the sync intervals.
    // So this code ensures that we refresh periodic sync upon any change to the
    // config
    if (!Objects.equals(oldModel.getConfig(), newModel.getConfig())) {
      UserStorageProviderModel oldProvider = new UserStorageProviderModel(oldModel);
      UserStorageProviderModel newProvider = new UserStorageProviderModel(newModel);

      // Only refresh periodic sync here if the intervals have not changed, otherwise
      // it would be done twice.
      // It might not do any harm, but there is no need to make Keycloak do more work
      // than necesary
      if (oldProvider.getChangedSyncPeriod() == newProvider.getChangedSyncPeriod()
          && oldProvider.getFullSyncPeriod() == newProvider.getFullSyncPeriod()) {
        logger.debug("Ensure periodic sync is refreshed if there are any changes to the config");
        StoreSyncEvent.fire(session, realm, newProvider, false);
      }
    }
  }

  private SynchronizationResult syncImpl(KeycloakSessionFactory sessionFactory, String realmId,
      UserStorageProviderModel model) {
    MsgAdminEventLogger adminEventLogger = new MsgAdminEventLogger(sessionFactory, realmId);

    KeycloakSession session = sessionFactory.create();

    RealmModel realm = session.realms().getRealm(realmId);

    EmailSenderProvider emailSenderProvider = session.getProvider(EmailSenderProvider.class);

    try {
      adminEventLogger.Log(String.format("user-storage/%s/sync-starting", model.getName()),
          String.format("Starting MSG user synchronization for '%s'", model.getName()));
    } catch (Exception e) {
      logger.errorf(e, "MSG error logging");
    }

    SynchronizationResult synchronizationResult = new SynchronizationResult();
    List<String> errors = new ArrayList<>();

    boolean hasImportFinished = false;

    try {
      String token = getMsgApiToken(model.get(CONFIG_KEY_AUTHORITY), model.get(CONFIG_KEY_CLIENT_ID),
          model.get(CONFIG_KEY_SECRET),
          model.get(CONFIG_KEY_SCOPE));

      GroupMapConfig groupMapConfig = GetGroupMapConfig(sessionFactory, realmId, model);

      try {
        List<MsgApiUser> apiUsers = getMsgApiUsers(model.get(CONFIG_KEY_MSG_BASE_URL), token, groupMapConfig,
            model.get(CONFIG_KEY_IMPORT_USERS_NOT_IN_MAPPED_GROUPS, false));

        try {
          String allowUpdateUpnDomainsCommaSeparated = model.get(CONFIG_KEY_ALLOW_UPDATE_UPN_DOMAINS);
          List<String> allowUpdateUpnDomains = null;
          if (allowUpdateUpnDomainsCommaSeparated != null && allowUpdateUpnDomainsCommaSeparated.length() > 0) {
            allowUpdateUpnDomains = Arrays.stream(allowUpdateUpnDomainsCommaSeparated.split(",")).map(d -> d.trim())
                .collect(Collectors.toList());
          }

          Boolean doNotOverrideMobileWithEmpty = model.get(CONFIG_KEY_DO_NOT_OVERRIDE_MOBILE_WITH_EMPTY, false);

          MsgApiUserResult result = importApiUsers(sessionFactory, realmId, model, apiUsers, allowUpdateUpnDomains,
              groupMapConfig, doNotOverrideMobileWithEmpty);

          synchronizationResult = result.synchronizationResult;
          errors = result.errors;

          hasImportFinished = true;
        } catch (Exception e) {
          logger.errorf(e, "Error importing api users for federation provider '%s'!",
              model.getName());
          errors.add(
              String.format("Error importing api users for federation provider '%s'! Exception:<br/>%s",
                  model.getName(), getErrorMessage(e)));
          synchronizationResult.setFailed(1);
        }
      } catch (Exception e) {
        logger.errorf(e, "Error getting users for federation provider '%s'. Please check Microsoft Graph API Base Url!",
            model.getName());
        errors.add(String.format(
            "Error getting users for federation provider '%s'. Please check Microsoft Graph API Base Url! Exception:<br/>%s",
            model.getName(), getErrorMessage(e)));
        synchronizationResult.setFailed(1);
      }
    } catch (Exception e) {
      logger.errorf(e,
          "Error getting token for federation provider '%s'. Please check Authority, client ID, secret and scope!",
          model.getName());
      errors.add(String.format(
          "Error getting token for federation provider '%s'. Please check Authority, client ID, secret and scope! Exception:<br/>%s",
          model.getName(), getErrorMessage(e)));
      synchronizationResult.setFailed(1);
    }

    if (hasImportFinished) {
      adminEventLogger.Log(String.format("user-storage/%s/sync-finished", model.getName()), synchronizationResult);

      if (synchronizationResult.getFailed() > 0) {
        try {
          String body = String.format(
              "Error during user synchronization for federation provider '%s' in realm: '%s'. %s users failed syncing. Errors:<br/><br/>%s",
              model.getName(), realm.getName(), synchronizationResult.getFailed(), String.join("<br/><br/>", errors));

          emailSenderProvider.send(realm.getSmtpConfig(), "log.rmgroup@f24.com", "Error in user sync", body, body);
        } catch (EmailException ex) {
          logger.errorf(ex, "Failed to send email");
        }
      }
    } else {
      adminEventLogger.Log(String.format("user-storage/%s/sync-error", model.getName()),
          "See server log for more details!");

      try {
        String body = String.format(
            "Error during user synchronization for federation provider '%s' in realm: '%s'. Errors:<br/><br/>%s",
            model.getName(), realm.getName(), String.join("<br/><br/>", errors));

        emailSenderProvider.send(realm.getSmtpConfig(), "log.rmgroup@f24.com", "Error in user sync", body, body);
      } catch (EmailException ex) {
        logger.errorf(ex, "Failed to send email");
      }
    }

    return synchronizationResult;
  }

  class GroupMapConfig {
    private Map<String, GroupModel> groupMap = new HashMap<>();

    private List<GroupModel> groupsForUsersNotInMappedGroups = new ArrayList<>();

    private List<String> errors = new ArrayList<>();

    public Map<String, GroupModel> getGroupMap() {
      return groupMap;
    }

    public List<GroupModel> GetGroupsForUsersNotInMappedGroups() {
      return groupsForUsersNotInMappedGroups;
    }

    public List<String> getErrors() {
      return errors;
    }

    public void setProperties(GroupMapConfig groupMapConfig) {
      groupMap = groupMapConfig.groupMap;
      groupsForUsersNotInMappedGroups = groupMapConfig.groupsForUsersNotInMappedGroups;
      errors = groupMapConfig.errors;
    }
  }

  private GroupMapConfig GetGroupMapConfig(KeycloakSessionFactory sessionFactory, final String realmId,
      ComponentModel config) {
    final GroupMapConfig groupMapConfig = new GroupMapConfig();
    KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
      RealmModel realm = session.realms().getRealm(realmId);
      groupMapConfig.setProperties(GetGroupMapConfig(session, realm, config));
    });
    return groupMapConfig;
  }

  private GroupMapConfig GetGroupMapConfig(KeycloakSession session, RealmModel realm, ComponentModel config) {
    GroupMapConfig groupMapConfig = new GroupMapConfig();
    Map<String, GroupModel> groupMap = groupMapConfig.groupMap;
    List<GroupModel> groupsForUsersNotInMappedGroups = groupMapConfig.groupsForUsersNotInMappedGroups;
    List<String> errors = groupMapConfig.errors;

    if (config.contains(CONFIG_KEY_GROUP_MAP)) {
      String json = config.get(CONFIG_KEY_GROUP_MAP);

      try {
        Map<String, Object> jsonMap = new JSONObject(json).toMap();
        jsonMap.forEach((k, v) -> {
          try {
            GroupModel kcGroup = KeycloakModelUtils.findGroupByPath(session, realm, v.toString());
            if (kcGroup != null) {
              groupMap.put(k, kcGroup);
            } else {
              String errorMessage = String.format("Keycloak group '%s' not found.", v);
              logger.error(errorMessage);
              errors.add(errorMessage);
            }
          } catch (Exception e) {
            String errorMessage = String.format("Error getting Keycloak group '%s'. '%s'", v, e.getMessage());
            logger.error(errorMessage, e);
            errors.add(errorMessage);
          }
        });
      } catch (JSONException e) {
        String errorMessage = String.format("Error in group map JSON '%s'. '%s'", json, e.getMessage());
        logger.error(errorMessage, e);
        errors.add(errorMessage);
      }
    }

    if (config.contains(CONFIG_KEY_GROUPS_FOR_USERS_NOT_IN_MAPPED_GROUPS)
        && config.contains(CONFIG_KEY_IMPORT_USERS_NOT_IN_MAPPED_GROUPS)) {
      Arrays.stream(config.get(CONFIG_KEY_GROUPS_FOR_USERS_NOT_IN_MAPPED_GROUPS).split(",")).map(g -> g.trim())
          .forEach(g -> {
            try {
              GroupModel kcGroup = KeycloakModelUtils.findGroupByPath(session, realm, g);
              if (kcGroup != null) {
                groupsForUsersNotInMappedGroups.add(kcGroup);
              } else {
                String errorMessage = String.format("Keycloak group '%s' not found.", g);
                logger.error(errorMessage);
                errors.add(errorMessage);
              }
            } catch (Exception e) {
              String errorMessage = String.format("Error getting Keycloak group '%s'. '%s'", g, e.getMessage());
              logger.error(errorMessage, e);
              errors.add(errorMessage);
            }
          });
    }

    return groupMapConfig;
  }

  private MsgApiUserResult importApiUsers(KeycloakSessionFactory sessionFactory, final String realmId,
      final ComponentModel fedModel, List<MsgApiUser> apiUsers, List<String> allowUpdateUpnDomains,
      GroupMapConfig groupMapConfig, Boolean doNotOverrideMobileWithEmpty) {
    final Map<String, GroupModel> groupMap = groupMapConfig.groupMap;
    final List<GroupModel> groupsForUsersNotInMappedGroups = groupMapConfig.groupsForUsersNotInMappedGroups;

    final String fedId = fedModel.getId();

    final Set<String> apiUsersUpnSet = apiUsers.stream().map(u -> u.getUserPrincipalName()).distinct()
        .collect(Collectors.toSet());

    final List<String> errors = new ArrayList<>();

    final AtomicInteger removedCount = new AtomicInteger(0);
    final AtomicInteger addedCount = new AtomicInteger(0);
    final AtomicInteger updatedCount = new AtomicInteger(0);
    final AtomicInteger failedCount = new AtomicInteger(0);

    final int totalExistingUsers = KeycloakModelUtils.runJobInTransactionWithResult(sessionFactory,
        (KeycloakSession session) -> {
          try {
            RealmModel realm = session.realms().getRealm(realmId);
            session.getContext().setRealm(realm);
            UserProvider userProvider = session.users();
            return userProvider.getUsersCount(realm);
          } catch (Exception e) {
            logger.errorf(e,
                "Error getting user count in federation provider '%s'. Will not be able to remove non existing users!",
                fedModel.getName());
            errors.add(String.format(
                "Error getting user count in federation provider '%s'. Will not be able to remove non existing users! Exception:<br/>%s",
                fedModel.getName(), getErrorMessage(e)));
            return -1;
          }
        });

    if (totalExistingUsers > 0) {
      int totalPagesExistingUsers = (int) Math.ceil((double) totalExistingUsers / USER_REMOVE_PAGE_SIZE);

      CopyOnWriteArrayList<UserModel> usersToRemove = new CopyOnWriteArrayList<>();

      IntStream.range(0, totalPagesExistingUsers).parallel().forEach(page -> {
        KeycloakModelUtils.runJobInTransaction(sessionFactory, (KeycloakSession session) -> {
          RealmModel realm = session.realms().getRealm(realmId);
          session.getContext().setRealm(realm);
          UserProvider userProvider = session.users();
          int firstResult = page * USER_REMOVE_PAGE_SIZE;
          int maxResults = USER_REMOVE_PAGE_SIZE;

          try {
            usersToRemove.addAll(userProvider
                .searchForUserStream(realm, new HashMap<>(), firstResult, maxResults)
                .filter(u -> fedId.equals(u.getFederationLink()) && !apiUsersUpnSet.contains(u.getUsername()))
                .collect(Collectors.toList()));
          } catch (Exception e) {
            logger.errorf(e,
                "Error getting users to remove in federation provider '%s'. Might not be able to remove all non existing users!",
                fedModel.getName());
            errors.add(String.format(
                "Error getting users to remove in federation provider '%s'. Might not be able to remove all non existing users! Exception:<br/>%s",
                fedModel.getName(), getErrorMessage(e)));
          }
        });
      });

      int totalUsersToRemove = usersToRemove.size();

      if (totalUsersToRemove > 0) {
        int totalPagesUsersToRemove = (int) Math.ceil((double) totalUsersToRemove / USER_REMOVE_PAGE_SIZE);
        IntStream.range(0, totalPagesUsersToRemove).parallel().forEach(page -> {

          KeycloakModelUtils.runJobInTransaction(sessionFactory, (KeycloakSession session) -> {
            RealmModel realm = session.realms().getRealm(realmId);
            session.getContext().setRealm(realm);
            UserProvider userProvider = session.users();

            int startIndex = page * USER_REMOVE_PAGE_SIZE;
            int endIndex = Math.min(startIndex + USER_REMOVE_PAGE_SIZE, totalUsersToRemove);

            List<UserModel> usersToRemovePage = usersToRemove.subList(startIndex, endIndex);

            for (final UserModel user : usersToRemovePage) {
              try {
                userProvider.removeUser(realm, user);
                removedCount.incrementAndGet();
              } catch (Exception e) {
                logger.errorf(e,
                    "Error removing non existing user with username '%s' in federation provider '%s'",
                    user.getUsername(), fedModel.getName());
                errors.add(String.format(
                    "Error removing non existing user with username '%s' in federation provider '%s'. Exception:<br/>%s",
                    user.getUsername(), fedModel.getName(), getErrorMessage(e)));
                failedCount.incrementAndGet();
              }
            }
          });
        });
      }
    }

    int totalApiUsers = apiUsers.size();

    if (totalApiUsers > 0) {
      int totalPages = (int) Math.ceil((double) totalApiUsers / USER_IMPORT_PAGE_SIZE);
      IntStream.range(0, totalPages).parallel().forEach(page -> {
        KeycloakModelUtils.runJobInTransaction(sessionFactory, (KeycloakSession session) -> {
          RealmModel realm = session.realms().getRealm(realmId);
          session.getContext().setRealm(realm);
          UserProvider userProvider = session.users();

          int startIndex = page * USER_IMPORT_PAGE_SIZE;
          int endIndex = Math.min(startIndex + USER_IMPORT_PAGE_SIZE, totalApiUsers);

          List<MsgApiUser> apiUsersPage = apiUsers.subList(startIndex, endIndex);

          apiUsersPage.forEach(apiUser -> {
            try {
              UserModel importedUser;
              UserModel existingLocalUser = userProvider.getUserByUsername(realm, apiUser.getUserPrincipalName());
              if (existingLocalUser == null) {
                importedUser = userProvider.addUser(realm, apiUser.getUserPrincipalName());
              } else {
                if (fedId.equals(existingLocalUser.getFederationLink())) {
                  importedUser = existingLocalUser;
                } else if (allowUpdateUpnDomains != null) {
                  String upn = apiUser.getUserPrincipalName();
                  if (!allowUpdateUpnDomains.stream().anyMatch(domain -> upn.endsWith("@" + domain))) {
                    logger.warnf(
                        "User with userPrincipalName '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s' and UPN domain does not match any of '%s'",
                        apiUser.getUserPrincipalName(), fedModel.getName(), String.join(", ", allowUpdateUpnDomains));
                    errors.add(String.format(
                        "User with userPrincipalName '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s' and UPN domain does not match any of '%s'",
                        apiUser.getUserPrincipalName(), fedModel.getName(),
                        String.join(", ", allowUpdateUpnDomains)));
                    failedCount.incrementAndGet();
                    return;
                  }
                  importedUser = existingLocalUser;
                } else {
                  logger.warnf(
                      "User with userPrincipalName '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s'",
                      apiUser.getUserPrincipalName(), fedModel.getName());
                  errors.add(String.format(
                      "User with userPrincipalName '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s'",
                      apiUser.getUserPrincipalName(), fedModel.getName()));
                  failedCount.incrementAndGet();
                  return;
                }
              }

              boolean attributesChanged = !apiUserEqualsLocalUser(apiUser, existingLocalUser);

              if (attributesChanged) {
                importedUser.setFederationLink(fedId);
                importedUser.setEmail(apiUser.getMail());
                importedUser.setEmailVerified(true);
                importedUser.setFirstName(apiUser.getGivenName());
                importedUser.setLastName(apiUser.getSurname());
                String mobilePhone = apiUser.getMobilePhone();
                if (!Strings.isNullOrEmpty(mobilePhone) || !doNotOverrideMobileWithEmpty) {
                  importedUser.setSingleAttribute("mobile", mobilePhone);
                }
                importedUser.setEnabled(apiUser.getAccountEnabled());
              }

              boolean groupsChanged = false;

              Set<String> apiUserGroups = apiUser.getGroups();

              HashSet<String> groupIds = new HashSet<>();

              if (groupMap != null && !groupMap.isEmpty() && apiUserGroups != null && !apiUserGroups.isEmpty()) {
                for (String apiUserGroup : apiUserGroups) {
                  if (groupMap.containsKey(apiUserGroup)) {
                    GroupModel kcGroup = groupMap.get(apiUserGroup);
                    groupIds.add(kcGroup.getId());
                    if (!importedUser.isMemberOf(kcGroup)) {
                      groupsChanged = true;
                      importedUser.joinGroup(kcGroup);
                    }
                  }
                }
                List<GroupModel> groupsToLeave = importedUser.getGroupsStream().filter(g -> {
                  return !groupIds.contains(g.getId());
                }).collect(Collectors.toList());

                if (!groupsToLeave.isEmpty()) {
                  groupsChanged = true;
                  groupsToLeave.forEach(g -> {
                    importedUser.leaveGroup(g);
                  });
                }
              } else {
                if ((apiUserGroups == null || apiUserGroups.isEmpty())
                    && !groupsForUsersNotInMappedGroups.isEmpty()) {
                  for (GroupModel g : groupsForUsersNotInMappedGroups) {
                    groupIds.add(g.getId());
                    if (!importedUser.isMemberOf(g)) {
                      groupsChanged = true;
                      importedUser.joinGroup(g);
                    }
                  }
                  List<GroupModel> groupsToLeave = importedUser.getGroupsStream().filter(g -> {
                    return !groupIds.contains(g.getId());
                  }).collect(Collectors.toList());

                  if (!groupsToLeave.isEmpty()) {
                    groupsChanged = true;
                    groupsToLeave.forEach(g -> {
                      importedUser.leaveGroup(g);
                    });
                  }
                } else {
                  List<GroupModel> groupsToLeave = importedUser.getGroupsStream().collect(Collectors.toList());

                  if (!groupsToLeave.isEmpty()) {
                    groupsChanged = true;
                    groupsToLeave.forEach(g -> {
                      importedUser.leaveGroup(g);
                    });
                  }
                }
              }

              if (existingLocalUser == null) {
                addedCount.incrementAndGet();
              } else if (attributesChanged || groupsChanged) {
                updatedCount.incrementAndGet();
              }
            } catch (Exception e) {
              logger.errorf(e, "Failed during import of user '%s' from Microsoft Graph API",
                  apiUser.getUserPrincipalName());

              errors.add(String.format(
                  "Failed during import of user '%s' from Microsoft Graph API. Exception:<br/>%s",
                  apiUser.getUserPrincipalName(), getErrorMessage(e)));
              failedCount.incrementAndGet();
            }
          });
        });
      });
    }

    final MsgSynchronizationResult syncResult = new MsgSynchronizationResult();

    syncResult.setFailed(failedCount.get());
    syncResult.setAdded(addedCount.get());
    syncResult.setUpdated(updatedCount.get());
    syncResult.setRemoved(removedCount.get());
    syncResult.setFetched(totalApiUsers);

    return new MsgApiUserResult(syncResult, errors);
  }

  private static boolean apiUserEqualsLocalUser(MsgApiUser apiUser, UserModel existingLocalUser) {
    return existingLocalUser != null &&
        Objects.equals(apiUser.getUserPrincipalName(), existingLocalUser.getUsername()) &&
        Objects.equals(apiUser.getMail(), existingLocalUser.getEmail()) &&
        Objects.equals(apiUser.getGivenName(), existingLocalUser.getFirstName()) &&
        Objects.equals(apiUser.getSurname(), existingLocalUser.getLastName()) &&
        Objects.equals(apiUser.getMobilePhone(), existingLocalUser.getFirstAttribute("mobile")) &&
        apiUser.getAccountEnabled() == existingLocalUser.isEnabled();
  }

  private static String getMsgApiToken(String authority, String clientId, String secret, String scope)
      throws Exception {
    ConfidentialClientApplication app = ConfidentialClientApplication.builder(clientId,
        ClientCredentialFactory.createFromSecret(secret)).authority(authority).build();

    ClientCredentialParameters clientCredentialParam = ClientCredentialParameters.builder(
        Collections.singleton(scope))
        .build();

    CompletableFuture<IAuthenticationResult> future = app.acquireToken(clientCredentialParam);
    IAuthenticationResult result = future.get();

    return result.accessToken();
  }

  private static JSONObject callMsgGetEndpoint(URL endpointUrl, String token) throws IOException {
    URLConnection con = endpointUrl.openConnection();
    HttpURLConnection http = (HttpURLConnection) con;
    http.setRequestMethod("GET");
    http.setRequestProperty("Authorization", String.format("Bearer %s", token));
    http.setRequestProperty("Accept", "application/json");
    http.setDoOutput(true);

    try (InputStream inputStream = http.getInputStream()) {
      String text = new BufferedReader(
          new InputStreamReader(inputStream, StandardCharsets.UTF_8))
          .lines()
          .collect(Collectors.joining("\n"));
      return new JSONObject(text);
    }
  }

  private static List<JSONObject> fetchAllEntitiesFromMsgGetEndpoint(URL endpointUrl, String token)
      throws Exception {
    List<JSONObject> odataObjects = new ArrayList<>();
    URL odataNextLink = endpointUrl;

    do {
      JSONObject odataJsonObject = callMsgGetEndpoint(odataNextLink, token);
      JSONArray odataJsonArray = odataJsonObject.getJSONArray("value");
      odataObjects.addAll(IntStream.range(0, odataJsonArray.length()).mapToObj(i -> {
        return odataJsonArray.getJSONObject(i);
      }).collect(Collectors.toList()));
      if (odataJsonObject.has("@odata.nextLink")) {
        try {
          odataNextLink = new URL(odataJsonObject.getString("@odata.nextLink"));
        } catch (MalformedURLException | JSONException e) {
          odataNextLink = null;
          logger.error("Unable to get @odata.nextLink", e);
        }
      } else {
        odataNextLink = null;
      }
    } while (odataNextLink != null);

    return odataObjects;
  }

  private static Map<String, String> getMsgApiGroupIdsAndMapKeys(String msgBaseUrl, String token,
      Map<String, GroupModel> groupMap) throws Exception {
    URI baseUri = new URI(msgBaseUrl);

    Set<String> groupMapKeySet = groupMap.keySet();

    Set<String> groupMapUUIDSet = groupMapKeySet.stream().filter(k -> {
      try {
        UUID.fromString(k);
        return true;
      } catch (Exception e) {
        return false;
      }
    }).collect(Collectors.toSet());

    Set<String> groupMapDisplayNameSet = new HashSet<>(groupMapKeySet);
    groupMapDisplayNameSet.removeAll(groupMapUUIDSet);

    Map<String, String> groupIdsAndMapKeys = new HashMap<>();

    if (!groupMapUUIDSet.isEmpty()) {
      groupIdsAndMapKeys.putAll(groupMapUUIDSet.stream().collect(Collectors.toMap(k -> k, k -> k)));
    }

    if (!groupMapDisplayNameSet.isEmpty()) {
      // We split the groupMapDisplayNameSet into chunks of 15 groups to avoid hitting
      // the max filters of 15 for the $filter query in the Microsoft Graph API
      // See:
      // https://learn.microsoft.com/en-us/graph/filter-query-parameter?tabs=http#operators-and-functions-supported-in-filter-expressions
      int chunkSize = 15;
      int arraySize = (int) Math.ceil(groupMapDisplayNameSet.size() / (double) chunkSize);
      List<Set<String>> groupMapDisplayNameChunks = new ArrayList<>(arraySize);
      String[] groupMapDisplayNameArray = groupMapDisplayNameSet.toArray(new String[0]);

      for (int i = 0; i < groupMapDisplayNameArray.length; i += chunkSize) {
        String[] groupArray = Arrays.copyOfRange(groupMapDisplayNameArray, i,
            Math.min(groupMapDisplayNameArray.length, i + chunkSize));
        Set<String> setToAdd = new HashSet<>(Arrays.asList(groupArray));
        groupMapDisplayNameChunks.add(setToAdd);
      }

      for (Set<String> subSet : groupMapDisplayNameChunks) {
        String displayNameFilter = URLEncoder
            .encode(
                String.format("displayName in (%s)",
                    String.join(",",
                        subSet.stream().map(k -> String.format("'%s'", k)).collect(Collectors.toList()))),
                StandardCharsets.UTF_8.name());

        URL groupsUrl = baseUri
            .resolve(String.format("./groups?$top=999&$select=id,displayName&$filter=%s", displayNameFilter))
            .toURL();

        List<JSONObject> groups = fetchAllEntitiesFromMsgGetEndpoint(groupsUrl, token);

        groupIdsAndMapKeys
            .putAll(groups.stream().collect(Collectors.toMap(o -> o.getString("id"), o -> o.getString("displayName"))));
      }
    }

    return groupIdsAndMapKeys;
  }

  private static List<MsgApiUser> getMsgApiUsers(String msgBaseUrl, String token, GroupMapConfig groupMapConfig,
      boolean importUsersNotInMappedGroups)
      throws Exception {
    final Map<String, GroupModel> groupMap = groupMapConfig.groupMap;
    final Map<String, MsgApiUser> usersMap = new HashMap<>();

    URI baseUri = new URI(msgBaseUrl);

    if (groupMap != null && !groupMap.isEmpty()) {
      Map<String, String> groupIdsAndMapKeys = getMsgApiGroupIdsAndMapKeys(msgBaseUrl, token, groupMap);

      groupIdsAndMapKeys.forEach((groupId, groupMapKey) -> {
        try {
          URL transitiveMembersUrl = baseUri.resolve(String.format(
              "./groups/%s/transitiveMembers?$top=999&$select=userPrincipalName,mail,givenName,surname,mobilePhone,accountEnabled",
              groupId)).toURL();

          List<JSONObject> users = fetchAllEntitiesFromMsgGetEndpoint(transitiveMembersUrl, token)
              .stream()
              .filter(o -> {
                String odataType = o.getString("@odata.type");
                return odataType.equals("#microsoft.graph.user") && !o.optString("mail").isEmpty();
              }).collect(Collectors.toList());

          users.forEach(u -> {
            String userPrincipalName = u.getString("userPrincipalName");
            MsgApiUser user;
            if (usersMap.containsKey(userPrincipalName)) {
              user = usersMap.get(userPrincipalName);
            } else {
              user = new MsgApiUser(userPrincipalName, u.getString("mail"), u.optString("givenName"),
                  u.optString("surname"), u.optString("mobilePhone"), u.optBoolean("accountEnabled", false));
              usersMap.put(userPrincipalName, user);
            }
            if (!user.getGroups().contains(groupMapKey)) {
              user.addGroup(groupMapKey);
            }
          });
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      });
    }

    if (importUsersNotInMappedGroups) {
      URL usersUrl = baseUri
          .resolve("./users?$top=999&$select=userPrincipalName,mail,givenName,surname,mobilePhone,accountEnabled")
          .toURL();

      List<JSONObject> users = fetchAllEntitiesFromMsgGetEndpoint(usersUrl, token).stream().filter(u -> {
        String userPrincipalName = u.getString("userPrincipalName");
        return !usersMap.containsKey(userPrincipalName) && !u.optString("mail").isEmpty();
      }).collect(Collectors.toList());

      users.forEach(u -> {
        String userPrincipalName = u.getString("userPrincipalName");
        usersMap.put(userPrincipalName, new MsgApiUser(userPrincipalName, u.getString("mail"), u.optString("givenName"),
            u.optString("surname"), u.optString("mobilePhone"), u.optBoolean("accountEnabled", false)));
      });
    }

    return usersMap.values().stream().collect(Collectors.toList());
  }

  private String getErrorMessage(Throwable e) {
    String errorMessage = e.getMessage();
    Throwable cause = e.getCause();

    if (cause != null) {
      errorMessage += "<br/>Caused by: " + getErrorMessage(cause);
    }

    return errorMessage;
  }
}
