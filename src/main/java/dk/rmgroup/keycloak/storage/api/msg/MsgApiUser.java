package dk.rmgroup.keycloak.storage.api.msg;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

public class MsgApiUser {
  private final String userPrincipalName;
  private final String mail;
  private final String givenName;
  private final String surname;
  private final String mobilePhone;
  private final boolean accountEnabled;
  private final Set<String> groups;

  public MsgApiUser(String userPrincipalName, String mail, String givenName, String surname, String mobilePhone, boolean accountEnabled) {
    this.userPrincipalName = Optional.ofNullable(userPrincipalName).map(String::toLowerCase).orElse(userPrincipalName);
    this.mail = Optional.ofNullable(mail).map(String::toLowerCase).orElse(mail);
    this.givenName = givenName;
    this.surname = surname;
    this.mobilePhone = mobilePhone;
    this.accountEnabled = accountEnabled;
    this.groups = new HashSet<>();
  }

  public String getUserPrincipalName() {
    return userPrincipalName;
  }

  public String getMail() {
    return mail;
  }

  public String getGivenName() {
    return givenName;
  }

  public String getSurname() {
    return surname;
  }

  public String getMobilePhone() {
    return mobilePhone;
  }

  public boolean getAccountEnabled() {
    return accountEnabled;
  }

  public Set<String> getGroups() {
    return groups;
  }

  public void addGroup(String group) {
    if (!groups.contains(group)) {
      groups.add(group);
    }
  }
}
