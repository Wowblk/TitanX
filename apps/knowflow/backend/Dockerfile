FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /workspace

COPY backend/pom.xml ./pom.xml
RUN mvn -q -DskipTests dependency:go-offline

COPY backend/src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app

COPY --from=build /workspace/target/knowflow-1.0-SNAPSHOT.jar /app/knowflow.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/knowflow.jar"]

