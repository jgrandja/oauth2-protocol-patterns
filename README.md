# OAuth 2.0 Protocols and Patterns

## Initial Setup

- Set the `ext.tomcatHomeDir` in `uaa-server/build.gradle` to the local distribution of Tomcat 8.x
- Download UAA -> `./gradlew -b uaa-server/build.gradle downloadUAA`

## Run the Sample

- Build the sample -> `./gradlew clean build`
- Run UAA Server -> `./gradlew -b uaa-server/build.gradle cargoRunLocal`
- Run Gateway -> `./gradlew -b gateway/build.gradle bootRun`
- Run Microservice A -> `./gradlew -b microservice-a/build.gradle bootRun`
- Run Microservice B -> `./gradlew -b microservice-b/build.gradle bootRun`
- Run Microservice C -> `./gradlew -b microservice-c/build.gradle bootRun`
- Go to `http://localhost:8080` and login to UAA using one of the registered users in `uaa-server/uaa.yml` under `scim.users`
