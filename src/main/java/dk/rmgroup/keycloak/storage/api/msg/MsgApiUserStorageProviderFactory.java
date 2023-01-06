package dk.rmgroup.keycloak.storage.api.msg;

import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_DEFAULT_AUTHORITY;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_DEFAULT_MSG_URL;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_DEFAULT_SCOPE;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_ALLOW_UPDATE_UPN_DOMAINS;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_AUTHORITY;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_CLIENT_ID;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_GROUPS_FOR_USERS_NOT_IN_MAPPED_GROUPS;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_GROUP_MAP;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_IMPORT_USERS_NOT_IN_MAPPED_GROUPS;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_MSG_BASE_URL;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_SCOPE;
import static dk.rmgroup.keycloak.storage.api.msg.MsgApiUserStorageProviderConstants.CONFIG_KEY_SECRET;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
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
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.jboss.logging.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.user.ImportSynchronization;
import org.keycloak.storage.user.SynchronizationResult;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;

public class MsgApiUserStorageProviderFactory
    implements UserStorageProviderFactory<MsgApiUserStorageProvider>, ImportSynchronization {

  protected final List<ProviderConfigProperty> configMetadata;

  private static final Logger logger = Logger.getLogger(MsgApiUserStorageProviderFactory.class);

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

    GroupMapConfig groupMapConfig = GetGroupMapConfig(realm, config);

    if (groupMapConfig.errors.size() > 0) {
      throw new ComponentValidationException(
          String.format("Errors found in Group map: %s", String.join(", ", groupMapConfig.errors)));
    }

    if (groupMapConfig.groupMap.size() == 0 && !config.get(CONFIG_KEY_IMPORT_USERS_NOT_IN_MAPPED_GROUPS, false)) {
      throw new ComponentValidationException(
          "You must turn ON \"Import users not in mapped groups\", when Group map is not specified!");
    }

    if (config.contains(CONFIG_KEY_GROUPS_FOR_USERS_NOT_IN_MAPPED_GROUPS)
        && !config.get(CONFIG_KEY_IMPORT_USERS_NOT_IN_MAPPED_GROUPS, false)) {
      throw new ComponentValidationException(
          "\"Groups for users not in mapped groups\" is not applicable, when \"Import users not in mapped groups\" is turned OFF!");
    }

    UserStorageProviderFactory.super.validateConfiguration(session, realm, config);
  }

  private SynchronizationResult syncImpl(KeycloakSessionFactory sessionFactory, String realmId,
      UserStorageProviderModel model) {
    String token;
    try {
      token = getMsgApiToken(model.get(CONFIG_KEY_AUTHORITY), model.get(CONFIG_KEY_CLIENT_ID),
          model.get(CONFIG_KEY_SECRET),
          model.get(CONFIG_KEY_SCOPE));
    } catch (Exception e) {
      throw new RuntimeException(String.format(
          "Error getting token for federation provider '%s'. Please check Authority, client ID, secret and scope!",
          model.getName()), e);
    }
    GroupMapConfig groupMapConfig = GetGroupMapConfig(sessionFactory, realmId, model);
    List<MsgApiUser> apiUsers;
    try {
      apiUsers = getMsgApiUsers(model.get(CONFIG_KEY_MSG_BASE_URL), token, groupMapConfig,
          model.get(CONFIG_KEY_IMPORT_USERS_NOT_IN_MAPPED_GROUPS, false));
    } catch (Exception e) {
      throw new RuntimeException(
          String.format("Error getting users for federation provider '%s'. Please check Microsoft Graph API Base Url!",
              model.getName()),
          e);
    }

    String allowUpdateUpnDomainsCommaSeparated = model.get(CONFIG_KEY_ALLOW_UPDATE_UPN_DOMAINS);
    List<String> allowUpdateUpnDomains = null;
    if (allowUpdateUpnDomainsCommaSeparated != null && allowUpdateUpnDomainsCommaSeparated.length() > 0) {
      allowUpdateUpnDomains = Arrays.stream(allowUpdateUpnDomainsCommaSeparated.split(",")).map(d -> d.trim())
          .collect(Collectors.toList());
    }

    return importApiUsers(sessionFactory, realmId, model, apiUsers, allowUpdateUpnDomains, groupMapConfig);
  }

  class GroupMapConfig {
    private Map<String, GroupModel> groupMap = new HashMap<String, GroupModel>();

    private List<GroupModel> groupsForUsersNotInMappedGroups = new ArrayList<GroupModel>();

    private List<String> errors = new ArrayList<String>();

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
      groupMapConfig.setProperties(GetGroupMapConfig(realm, config));
    });
    return groupMapConfig;
  }

  private GroupMapConfig GetGroupMapConfig(RealmModel realm, ComponentModel config) {
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
            GroupModel kcGroup = KeycloakModelUtils.findGroupByPath(realm, v.toString());
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
      } catch (Exception e) {
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
              GroupModel kcGroup = KeycloakModelUtils.findGroupByPath(realm, g);
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

  private SynchronizationResult importApiUsers(KeycloakSessionFactory sessionFactory, final String realmId,
      final ComponentModel fedModel, List<MsgApiUser> apiUsers, List<String> allowUpdateUpnDomains,
      GroupMapConfig groupMapConfig) {
    final Map<String, GroupModel> groupMap = groupMapConfig.groupMap;
    final List<GroupModel> groupsForUsersNotInMappedGroups = groupMapConfig.groupsForUsersNotInMappedGroups;

    final SynchronizationResult syncResult = new SynchronizationResult();

    final String fedId = fedModel.getId();

    final Set<String> apiUsersUpnSet = apiUsers.stream().map(u -> u.getUserPrincipalName().toLowerCase()).distinct()
        .collect(Collectors.toSet());

    KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

      @Override
      public void run(KeycloakSession session) {
        try {
          RealmModel realm = session.realms().getRealm(realmId);
          UserProvider userProvider = session.users();
          List<UserModel> usersToRemove = userProvider.getUsersStream(realm)
              .filter(u -> fedId.equals(u.getFederationLink()) && !apiUsersUpnSet.contains(u.getUsername()))
              .collect(Collectors.toList());
          for (final UserModel user : usersToRemove) {
            try {
              userProvider.removeUser(realm, user);
              syncResult.increaseRemoved();
            } catch (Exception e) {
              logger.errorf(e, "Error removing non existing user with username '%s' in federation provider '%s'",
                  user.getUsername(), fedModel.getName());
              syncResult.increaseFailed();
            }
          }
        } catch (Exception e) {
          logger.errorf(e, "Error getting users to remove in federation provider '%s'", fedModel.getName());
        }
      }
    });

    for (final MsgApiUser apiUser : apiUsers) {
      try {
        KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

          @Override
          public void run(KeycloakSession session) {
            RealmModel realm = session.realms().getRealm(realmId);
            UserProvider userProvider = session.users();
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
                  syncResult.increaseFailed();
                  return;
                }
                importedUser = existingLocalUser;
              } else {
                logger.warnf(
                    "User with userPrincipalName '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s'",
                    apiUser.getUserPrincipalName(), fedModel.getName());
                syncResult.increaseFailed();
                return;
              }
            }
            importedUser.setFederationLink(fedId);
            importedUser.setEmail(apiUser.getMail());
            importedUser.setEmailVerified(true);
            importedUser.setFirstName(apiUser.getGivenName());
            importedUser.setLastName(apiUser.getSurname());
            importedUser.setSingleAttribute("mobile", apiUser.getMobilePhone());
            importedUser.setEnabled(apiUser.getAccountEnabled());

            Set<String> apiUserGroups = apiUser.getGroups();

            HashSet<String> groupIds = new HashSet<String>();

            if (groupMap != null && groupMap.size() > 0 && apiUserGroups != null && apiUserGroups.size() > 0) {
              for (String apiUserGroup : apiUserGroups) {
                if (groupMap.containsKey(apiUserGroup)) {
                  GroupModel kcGroup = groupMap.get(apiUserGroup);
                  groupIds.add(kcGroup.getId());
                  if (!importedUser.isMemberOf(kcGroup)) {
                    importedUser.joinGroup(kcGroup);
                  }
                }
              }
              importedUser.getGroupsStream().filter(g -> {
                return !groupIds.contains(g.getId());
              }).forEach(g -> {
                importedUser.leaveGroup(g);
              });
            } else {
              if (apiUserGroups.size() == 0 && groupsForUsersNotInMappedGroups.size() > 0) {
                groupsForUsersNotInMappedGroups.forEach(g -> {
                  groupIds.add(g.getId());
                  if (!importedUser.isMemberOf(g)) {
                    importedUser.joinGroup(g);
                  }
                });
                importedUser.getGroupsStream().filter(g -> {
                  return !groupIds.contains(g.getId());
                }).forEach(g -> {
                  importedUser.leaveGroup(g);
                });
              } else {
                importedUser.getGroupsStream().forEach(g -> {
                  importedUser.leaveGroup(g);
                });
              }
            }

            if (existingLocalUser == null) {
              syncResult.increaseAdded();
            } else {
              syncResult.increaseUpdated();
            }
          }
        });
      } catch (Exception e) {
        logger.errorf(e, "Failed during import of user '%s' from Microsoft Graph API", apiUser.getUserPrincipalName());
        syncResult.increaseFailed();
      }
    }

    return syncResult;
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
    List<JSONObject> odataObjects = new ArrayList<JSONObject>();
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
        } catch (Exception e) {
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

    Set<String> groupMapDisplayNameSet = new HashSet<String>(groupMapKeySet);
    groupMapDisplayNameSet.removeAll(groupMapUUIDSet);

    Map<String, String> groupIdsAndMapKeys = new HashMap<String, String>();

    if (groupMapUUIDSet.size() > 0) {
      groupIdsAndMapKeys.putAll(groupMapKeySet.stream().collect(Collectors.toMap(k -> k, k -> k)));
    }

    if (groupMapDisplayNameSet.size() > 0) {
      String displayNameFilter = URLEncoder
          .encode(
              String.format("displayName in (%s)",
                  String.join(",",
                      groupMapDisplayNameSet.stream().map(k -> String.format("'%s'", k)).collect(Collectors.toList()))),
              StandardCharsets.UTF_8.name());

      URL groupsUrl = baseUri
          .resolve(String.format("./groups?$top=999&$select=id,displayName&$filter=%s", displayNameFilter))
          .toURL();

      List<JSONObject> groups = fetchAllEntitiesFromMsgGetEndpoint(groupsUrl, token);

      groupIdsAndMapKeys
          .putAll(groups.stream().collect(Collectors.toMap(o -> o.getString("id"), o -> o.getString("displayName"))));
    }

    return groupIdsAndMapKeys;
  }

  private static List<MsgApiUser> getMsgApiUsers(String msgBaseUrl, String token, GroupMapConfig groupMapConfig,
      boolean importUsersNotInMappedGroups)
      throws Exception {
    final Map<String, GroupModel> groupMap = groupMapConfig.groupMap;
    final Map<String, MsgApiUser> usersMap = new HashMap<>();

    URI baseUri = new URI(msgBaseUrl);

    if (groupMap != null && groupMap.size() > 0) {
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
}
