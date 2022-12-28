# Keycloak Microsoft Graph API User Federation

Keycloak user storage provider for allowing user federation via the Microsoft Graph API.

To make Keycloak recognize the user storage provider the src/main/resources/META-INF folder and its content is required.

## Build

Requirements are Maven (verified 3.6.3) and Java (verified openjdk 1.8.0_322).

To build a .jar file that can be used in Keycloak run the following command

```bash
mvn clean package
```

## Deploy

To deploy the user storage provider in Keycloak copy the .jar file into the `/opt/keycloak/providers` folder.

When deploying to Docker, copy the file before running `kc.sh build` in the Docker file.
