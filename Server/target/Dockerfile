FROM eclipse-temurin:21-jdk-alpine
WORKDIR /app
COPY target/Server-0.0.1-SNAPSHOT.jar app.jar
ENV PORT 8080
ENTRYPOINT ["java","-jar","/app.jar"]
