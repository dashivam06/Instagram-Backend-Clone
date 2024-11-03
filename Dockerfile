# Stage 1: Build the application
FROM maven:3.8.4-openjdk-17 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean package -DskipTest

# Stage 2: Create the runtime image
FROM openjdk:17-jdk-slim

COPY --from=build /app/target/instagram-0.0.1-SNAPSHOT.jar /usr/local/lib/app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/usr/local/lib/app.jar"]


ENTRYPOINT ["java", "-jar", "/app/target/instagram-0.0.1-SNAPSHOT.jar"]
