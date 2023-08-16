package dk.rmgroup.keycloak.storage.api.msg;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.keycloak.common.ClientConnection;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminEventBuilder;

public class MsgAdminEventLogger {
  private final KeycloakSessionFactory sessionFactory;
  private final String realmId;

  public MsgAdminEventLogger(KeycloakSessionFactory sessionFactory, String realmId) {
    this.sessionFactory = sessionFactory;
    this.realmId = realmId;
  }

  public void Log(String resourcePath, Object representation) {
    KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

      @Override
      public void run(KeycloakSession session) {
        Log(session, realmId, resourcePath, representation);
      }
    });
  }

  public static void Log(KeycloakSession session, String realmId, String resourcePath, Object representation) {
    RealmModel realm = session.realms().getRealm(realmId);
    AdminEventBuilder adminEventBuilder = new AdminEventBuilder(realm, getAdminAuth(realm), session,
        getClientConnection());

    adminEventBuilder
        .resource(ResourceType.USER_FEDERATION_PROVIDER)
        .resourcePath(resourcePath)
        .representation(representation)
        .operation(OperationType.ACTION)
        .success();
  }

  private static AdminAuth getAdminAuth(RealmModel realm) {
    return new AdminAuth(realm, new AccessToken(), getUserModel(), getClientModel());
  }

  private static UserModel getUserModel() {
    return new UserModel() {

      @Override
      public Stream<RoleModel> getRealmRoleMappingsStream() {
        throw new UnsupportedOperationException("Unimplemented method 'getRealmRoleMappingsStream'");
      }

      @Override
      public Stream<RoleModel> getClientRoleMappingsStream(ClientModel app) {
        throw new UnsupportedOperationException("Unimplemented method 'getClientRoleMappingsStream'");
      }

      @Override
      public boolean hasRole(RoleModel role) {
        throw new UnsupportedOperationException("Unimplemented method 'hasRole'");
      }

      @Override
      public void grantRole(RoleModel role) {
        throw new UnsupportedOperationException("Unimplemented method 'grantRole'");
      }

      @Override
      public Stream<RoleModel> getRoleMappingsStream() {
        throw new UnsupportedOperationException("Unimplemented method 'getRoleMappingsStream'");
      }

      @Override
      public void deleteRoleMapping(RoleModel role) {
        throw new UnsupportedOperationException("Unimplemented method 'deleteRoleMapping'");
      }

      @Override
      public String getId() {
        return null;
      }

      @Override
      public String getUsername() {
        throw new UnsupportedOperationException("Unimplemented method 'getUsername'");
      }

      @Override
      public void setUsername(String username) {
        throw new UnsupportedOperationException("Unimplemented method 'setUsername'");
      }

      @Override
      public Long getCreatedTimestamp() {
        throw new UnsupportedOperationException("Unimplemented method 'getCreatedTimestamp'");
      }

      @Override
      public void setCreatedTimestamp(Long timestamp) {
        throw new UnsupportedOperationException("Unimplemented method 'setCreatedTimestamp'");
      }

      @Override
      public boolean isEnabled() {
        throw new UnsupportedOperationException("Unimplemented method 'isEnabled'");
      }

      @Override
      public void setEnabled(boolean enabled) {
        throw new UnsupportedOperationException("Unimplemented method 'setEnabled'");
      }

      @Override
      public void setSingleAttribute(String name, String value) {
        throw new UnsupportedOperationException("Unimplemented method 'setSingleAttribute'");
      }

      @Override
      public void setAttribute(String name, List<String> values) {
        throw new UnsupportedOperationException("Unimplemented method 'setAttribute'");
      }

      @Override
      public void removeAttribute(String name) {
        throw new UnsupportedOperationException("Unimplemented method 'removeAttribute'");
      }

      @Override
      public String getFirstAttribute(String name) {
        throw new UnsupportedOperationException("Unimplemented method 'getFirstAttribute'");
      }

      @Override
      public Stream<String> getAttributeStream(String name) {
        throw new UnsupportedOperationException("Unimplemented method 'getAttributeStream'");
      }

      @Override
      public Map<String, List<String>> getAttributes() {
        throw new UnsupportedOperationException("Unimplemented method 'getAttributes'");
      }

      @Override
      public Stream<String> getRequiredActionsStream() {
        throw new UnsupportedOperationException("Unimplemented method 'getRequiredActionsStream'");
      }

      @Override
      public void addRequiredAction(String action) {
        throw new UnsupportedOperationException("Unimplemented method 'addRequiredAction'");
      }

      @Override
      public void removeRequiredAction(String action) {
        throw new UnsupportedOperationException("Unimplemented method 'removeRequiredAction'");
      }

      @Override
      public String getFirstName() {
        throw new UnsupportedOperationException("Unimplemented method 'getFirstName'");
      }

      @Override
      public void setFirstName(String firstName) {
        throw new UnsupportedOperationException("Unimplemented method 'setFirstName'");
      }

      @Override
      public String getLastName() {
        throw new UnsupportedOperationException("Unimplemented method 'getLastName'");
      }

      @Override
      public void setLastName(String lastName) {
        throw new UnsupportedOperationException("Unimplemented method 'setLastName'");
      }

      @Override
      public String getEmail() {
        throw new UnsupportedOperationException("Unimplemented method 'getEmail'");
      }

      @Override
      public void setEmail(String email) {
        throw new UnsupportedOperationException("Unimplemented method 'setEmail'");
      }

      @Override
      public boolean isEmailVerified() {
        throw new UnsupportedOperationException("Unimplemented method 'isEmailVerified'");
      }

      @Override
      public void setEmailVerified(boolean verified) {
        throw new UnsupportedOperationException("Unimplemented method 'setEmailVerified'");
      }

      @Override
      public Stream<GroupModel> getGroupsStream() {
        throw new UnsupportedOperationException("Unimplemented method 'getGroupsStream'");
      }

      @Override
      public void joinGroup(GroupModel group) {
        throw new UnsupportedOperationException("Unimplemented method 'joinGroup'");
      }

      @Override
      public void leaveGroup(GroupModel group) {
        throw new UnsupportedOperationException("Unimplemented method 'leaveGroup'");
      }

      @Override
      public boolean isMemberOf(GroupModel group) {
        throw new UnsupportedOperationException("Unimplemented method 'isMemberOf'");
      }

      @Override
      public String getFederationLink() {
        throw new UnsupportedOperationException("Unimplemented method 'getFederationLink'");
      }

      @Override
      public void setFederationLink(String link) {
        throw new UnsupportedOperationException("Unimplemented method 'setFederationLink'");
      }

      @Override
      public String getServiceAccountClientLink() {
        throw new UnsupportedOperationException("Unimplemented method 'getServiceAccountClientLink'");
      }

      @Override
      public void setServiceAccountClientLink(String clientInternalId) {
        throw new UnsupportedOperationException("Unimplemented method 'setServiceAccountClientLink'");
      }

      @Override
      public SubjectCredentialManager credentialManager() {
        throw new UnsupportedOperationException("Unimplemented method 'credentialManager'");
      }

    };
  }

  private static ClientModel getClientModel() {
    return new ClientModel() {

      @Override
      public Stream<ProtocolMapperModel> getProtocolMappersStream() {
        throw new UnsupportedOperationException("Unimplemented method 'getProtocolMappersStream'");
      }

      @Override
      public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
        throw new UnsupportedOperationException("Unimplemented method 'addProtocolMapper'");
      }

      @Override
      public void removeProtocolMapper(ProtocolMapperModel mapping) {
        throw new UnsupportedOperationException("Unimplemented method 'removeProtocolMapper'");
      }

      @Override
      public void updateProtocolMapper(ProtocolMapperModel mapping) {
        throw new UnsupportedOperationException("Unimplemented method 'updateProtocolMapper'");
      }

      @Override
      public ProtocolMapperModel getProtocolMapperById(String id) {
        throw new UnsupportedOperationException("Unimplemented method 'getProtocolMapperById'");
      }

      @Override
      public ProtocolMapperModel getProtocolMapperByName(String protocol, String name) {
        throw new UnsupportedOperationException("Unimplemented method 'getProtocolMapperByName'");
      }

      @Override
      public Stream<RoleModel> getScopeMappingsStream() {
        throw new UnsupportedOperationException("Unimplemented method 'getScopeMappingsStream'");
      }

      @Override
      public Stream<RoleModel> getRealmScopeMappingsStream() {
        throw new UnsupportedOperationException("Unimplemented method 'getRealmScopeMappingsStream'");
      }

      @Override
      public void addScopeMapping(RoleModel role) {
        throw new UnsupportedOperationException("Unimplemented method 'addScopeMapping'");
      }

      @Override
      public void deleteScopeMapping(RoleModel role) {
        throw new UnsupportedOperationException("Unimplemented method 'deleteScopeMapping'");
      }

      @Override
      public boolean hasScope(RoleModel role) {
        throw new UnsupportedOperationException("Unimplemented method 'hasScope'");
      }

      @Override
      public RoleModel getRole(String name) {
        throw new UnsupportedOperationException("Unimplemented method 'getRole'");
      }

      @Override
      public RoleModel addRole(String name) {
        throw new UnsupportedOperationException("Unimplemented method 'addRole'");
      }

      @Override
      public RoleModel addRole(String id, String name) {
        throw new UnsupportedOperationException("Unimplemented method 'addRole'");
      }

      @Override
      public boolean removeRole(RoleModel role) {
        throw new UnsupportedOperationException("Unimplemented method 'removeRole'");
      }

      @Override
      public Stream<RoleModel> getRolesStream() {
        throw new UnsupportedOperationException("Unimplemented method 'getRolesStream'");
      }

      @Override
      public Stream<RoleModel> getRolesStream(Integer firstResult, Integer maxResults) {
        throw new UnsupportedOperationException("Unimplemented method 'getRolesStream'");
      }

      @Override
      public Stream<RoleModel> searchForRolesStream(String search, Integer first, Integer max) {
        throw new UnsupportedOperationException("Unimplemented method 'searchForRolesStream'");
      }

      @Override
      public void updateClient() {
        throw new UnsupportedOperationException("Unimplemented method 'updateClient'");
      }

      @Override
      public String getId() {
        return null;
      }

      @Override
      public String getClientId() {
        throw new UnsupportedOperationException("Unimplemented method 'getClientId'");
      }

      @Override
      public void setClientId(String clientId) {
        throw new UnsupportedOperationException("Unimplemented method 'setClientId'");
      }

      @Override
      public String getName() {
        throw new UnsupportedOperationException("Unimplemented method 'getName'");
      }

      @Override
      public void setName(String name) {
        throw new UnsupportedOperationException("Unimplemented method 'setName'");
      }

      @Override
      public String getDescription() {
        throw new UnsupportedOperationException("Unimplemented method 'getDescription'");
      }

      @Override
      public void setDescription(String description) {
        throw new UnsupportedOperationException("Unimplemented method 'setDescription'");
      }

      @Override
      public boolean isEnabled() {
        throw new UnsupportedOperationException("Unimplemented method 'isEnabled'");
      }

      @Override
      public void setEnabled(boolean enabled) {
        throw new UnsupportedOperationException("Unimplemented method 'setEnabled'");
      }

      @Override
      public boolean isAlwaysDisplayInConsole() {
        throw new UnsupportedOperationException("Unimplemented method 'isAlwaysDisplayInConsole'");
      }

      @Override
      public void setAlwaysDisplayInConsole(boolean alwaysDisplayInConsole) {
        throw new UnsupportedOperationException("Unimplemented method 'setAlwaysDisplayInConsole'");
      }

      @Override
      public boolean isSurrogateAuthRequired() {
        throw new UnsupportedOperationException("Unimplemented method 'isSurrogateAuthRequired'");
      }

      @Override
      public void setSurrogateAuthRequired(boolean surrogateAuthRequired) {
        throw new UnsupportedOperationException("Unimplemented method 'setSurrogateAuthRequired'");
      }

      @Override
      public Set<String> getWebOrigins() {
        throw new UnsupportedOperationException("Unimplemented method 'getWebOrigins'");
      }

      @Override
      public void setWebOrigins(Set<String> webOrigins) {
        throw new UnsupportedOperationException("Unimplemented method 'setWebOrigins'");
      }

      @Override
      public void addWebOrigin(String webOrigin) {
        throw new UnsupportedOperationException("Unimplemented method 'addWebOrigin'");
      }

      @Override
      public void removeWebOrigin(String webOrigin) {
        throw new UnsupportedOperationException("Unimplemented method 'removeWebOrigin'");
      }

      @Override
      public Set<String> getRedirectUris() {
        throw new UnsupportedOperationException("Unimplemented method 'getRedirectUris'");
      }

      @Override
      public void setRedirectUris(Set<String> redirectUris) {
        throw new UnsupportedOperationException("Unimplemented method 'setRedirectUris'");
      }

      @Override
      public void addRedirectUri(String redirectUri) {
        throw new UnsupportedOperationException("Unimplemented method 'addRedirectUri'");
      }

      @Override
      public void removeRedirectUri(String redirectUri) {
        throw new UnsupportedOperationException("Unimplemented method 'removeRedirectUri'");
      }

      @Override
      public String getManagementUrl() {
        throw new UnsupportedOperationException("Unimplemented method 'getManagementUrl'");
      }

      @Override
      public void setManagementUrl(String url) {
        throw new UnsupportedOperationException("Unimplemented method 'setManagementUrl'");
      }

      @Override
      public String getRootUrl() {
        throw new UnsupportedOperationException("Unimplemented method 'getRootUrl'");
      }

      @Override
      public void setRootUrl(String url) {
        throw new UnsupportedOperationException("Unimplemented method 'setRootUrl'");
      }

      @Override
      public String getBaseUrl() {
        throw new UnsupportedOperationException("Unimplemented method 'getBaseUrl'");
      }

      @Override
      public void setBaseUrl(String url) {
        throw new UnsupportedOperationException("Unimplemented method 'setBaseUrl'");
      }

      @Override
      public boolean isBearerOnly() {
        throw new UnsupportedOperationException("Unimplemented method 'isBearerOnly'");
      }

      @Override
      public void setBearerOnly(boolean only) {
        throw new UnsupportedOperationException("Unimplemented method 'setBearerOnly'");
      }

      @Override
      public int getNodeReRegistrationTimeout() {
        throw new UnsupportedOperationException("Unimplemented method 'getNodeReRegistrationTimeout'");
      }

      @Override
      public void setNodeReRegistrationTimeout(int timeout) {
        throw new UnsupportedOperationException("Unimplemented method 'setNodeReRegistrationTimeout'");
      }

      @Override
      public String getClientAuthenticatorType() {
        throw new UnsupportedOperationException("Unimplemented method 'getClientAuthenticatorType'");
      }

      @Override
      public void setClientAuthenticatorType(String clientAuthenticatorType) {
        throw new UnsupportedOperationException("Unimplemented method 'setClientAuthenticatorType'");
      }

      @Override
      public boolean validateSecret(String secret) {
        throw new UnsupportedOperationException("Unimplemented method 'validateSecret'");
      }

      @Override
      public String getSecret() {
        throw new UnsupportedOperationException("Unimplemented method 'getSecret'");
      }

      @Override
      public void setSecret(String secret) {
        throw new UnsupportedOperationException("Unimplemented method 'setSecret'");
      }

      @Override
      public String getRegistrationToken() {
        throw new UnsupportedOperationException("Unimplemented method 'getRegistrationToken'");
      }

      @Override
      public void setRegistrationToken(String registrationToken) {
        throw new UnsupportedOperationException("Unimplemented method 'setRegistrationToken'");
      }

      @Override
      public String getProtocol() {
        throw new UnsupportedOperationException("Unimplemented method 'getProtocol'");
      }

      @Override
      public void setProtocol(String protocol) {
        throw new UnsupportedOperationException("Unimplemented method 'setProtocol'");
      }

      @Override
      public void setAttribute(String name, String value) {
        throw new UnsupportedOperationException("Unimplemented method 'setAttribute'");
      }

      @Override
      public void removeAttribute(String name) {
        throw new UnsupportedOperationException("Unimplemented method 'removeAttribute'");
      }

      @Override
      public String getAttribute(String name) {
        throw new UnsupportedOperationException("Unimplemented method 'getAttribute'");
      }

      @Override
      public Map<String, String> getAttributes() {
        throw new UnsupportedOperationException("Unimplemented method 'getAttributes'");
      }

      @Override
      public String getAuthenticationFlowBindingOverride(String binding) {
        throw new UnsupportedOperationException("Unimplemented method 'getAuthenticationFlowBindingOverride'");
      }

      @Override
      public Map<String, String> getAuthenticationFlowBindingOverrides() {
        throw new UnsupportedOperationException("Unimplemented method 'getAuthenticationFlowBindingOverrides'");
      }

      @Override
      public void removeAuthenticationFlowBindingOverride(String binding) {
        throw new UnsupportedOperationException("Unimplemented method 'removeAuthenticationFlowBindingOverride'");
      }

      @Override
      public void setAuthenticationFlowBindingOverride(String binding, String flowId) {
        throw new UnsupportedOperationException("Unimplemented method 'setAuthenticationFlowBindingOverride'");
      }

      @Override
      public boolean isFrontchannelLogout() {
        throw new UnsupportedOperationException("Unimplemented method 'isFrontchannelLogout'");
      }

      @Override
      public void setFrontchannelLogout(boolean flag) {
        throw new UnsupportedOperationException("Unimplemented method 'setFrontchannelLogout'");
      }

      @Override
      public boolean isFullScopeAllowed() {
        throw new UnsupportedOperationException("Unimplemented method 'isFullScopeAllowed'");
      }

      @Override
      public void setFullScopeAllowed(boolean value) {
        throw new UnsupportedOperationException("Unimplemented method 'setFullScopeAllowed'");
      }

      @Override
      public boolean isPublicClient() {
        throw new UnsupportedOperationException("Unimplemented method 'isPublicClient'");
      }

      @Override
      public void setPublicClient(boolean flag) {
        throw new UnsupportedOperationException("Unimplemented method 'setPublicClient'");
      }

      @Override
      public boolean isConsentRequired() {
        throw new UnsupportedOperationException("Unimplemented method 'isConsentRequired'");
      }

      @Override
      public void setConsentRequired(boolean consentRequired) {
        throw new UnsupportedOperationException("Unimplemented method 'setConsentRequired'");
      }

      @Override
      public boolean isStandardFlowEnabled() {
        throw new UnsupportedOperationException("Unimplemented method 'isStandardFlowEnabled'");
      }

      @Override
      public void setStandardFlowEnabled(boolean standardFlowEnabled) {
        throw new UnsupportedOperationException("Unimplemented method 'setStandardFlowEnabled'");
      }

      @Override
      public boolean isImplicitFlowEnabled() {
        throw new UnsupportedOperationException("Unimplemented method 'isImplicitFlowEnabled'");
      }

      @Override
      public void setImplicitFlowEnabled(boolean implicitFlowEnabled) {
        throw new UnsupportedOperationException("Unimplemented method 'setImplicitFlowEnabled'");
      }

      @Override
      public boolean isDirectAccessGrantsEnabled() {
        throw new UnsupportedOperationException("Unimplemented method 'isDirectAccessGrantsEnabled'");
      }

      @Override
      public void setDirectAccessGrantsEnabled(boolean directAccessGrantsEnabled) {
        throw new UnsupportedOperationException("Unimplemented method 'setDirectAccessGrantsEnabled'");
      }

      @Override
      public boolean isServiceAccountsEnabled() {
        throw new UnsupportedOperationException("Unimplemented method 'isServiceAccountsEnabled'");
      }

      @Override
      public void setServiceAccountsEnabled(boolean serviceAccountsEnabled) {
        throw new UnsupportedOperationException("Unimplemented method 'setServiceAccountsEnabled'");
      }

      @Override
      public RealmModel getRealm() {
        throw new UnsupportedOperationException("Unimplemented method 'getRealm'");
      }

      @Override
      public void addClientScope(ClientScopeModel clientScope, boolean defaultScope) {
        throw new UnsupportedOperationException("Unimplemented method 'addClientScope'");
      }

      @Override
      public void addClientScopes(Set<ClientScopeModel> clientScopes, boolean defaultScope) {
        throw new UnsupportedOperationException("Unimplemented method 'addClientScopes'");
      }

      @Override
      public void removeClientScope(ClientScopeModel clientScope) {
        throw new UnsupportedOperationException("Unimplemented method 'removeClientScope'");
      }

      @Override
      public Map<String, ClientScopeModel> getClientScopes(boolean defaultScope) {
        throw new UnsupportedOperationException("Unimplemented method 'getClientScopes'");
      }

      @Override
      public int getNotBefore() {
        throw new UnsupportedOperationException("Unimplemented method 'getNotBefore'");
      }

      @Override
      public void setNotBefore(int notBefore) {
        throw new UnsupportedOperationException("Unimplemented method 'setNotBefore'");
      }

      @Override
      public Map<String, Integer> getRegisteredNodes() {
        throw new UnsupportedOperationException("Unimplemented method 'getRegisteredNodes'");
      }

      @Override
      public void registerNode(String nodeHost, int registrationTime) {
        throw new UnsupportedOperationException("Unimplemented method 'registerNode'");
      }

      @Override
      public void unregisterNode(String nodeHost) {
        throw new UnsupportedOperationException("Unimplemented method 'unregisterNode'");
      }

    };
  }

  private static ClientConnection getClientConnection() {
    return new ClientConnection() {

      @Override
      public String getRemoteAddr() {
        return "127.0.0.1";
      }

      @Override
      public String getRemoteHost() {
        throw new UnsupportedOperationException("Unimplemented method 'getRemoteHost'");
      }

      @Override
      public int getRemotePort() {
        throw new UnsupportedOperationException("Unimplemented method 'getRemotePort'");
      }

      @Override
      public String getLocalAddr() {
        throw new UnsupportedOperationException("Unimplemented method 'getLocalAddr'");
      }

      @Override
      public int getLocalPort() {
        throw new UnsupportedOperationException("Unimplemented method 'getLocalPort'");
      }

    };
  }
}
