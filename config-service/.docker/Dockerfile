# --------------> The build image
FROM gradle:7-jdk17 as builder
ARG PROJECT_NAME
ARG BUILD_FILE=./${PROJECT_NAME}/build/libs/app.jar
VOLUME /tmp
WORKDIR app
COPY . .
RUN gradle :${PROJECT_NAME}:clean :${PROJECT_NAME}:bootJar --info --stacktrace
RUN java -Djarmode=layertools -jar ${BUILD_FILE} extract --destination /app/build/${PROJECT_NAME}
RUN rm -f ${BUILD_FILE}
# --------------> The production image
FROM eclipse-temurin:17-jre-alpine
ARG PROJECT_NAME
ARG ROOT_USER=newuser
ENV JAVA_OPTS="-server -XX:+UseZGC -Xmx128m"
RUN apk update && apk add --no-cache dumb-init
WORKDIR /app
RUN mkdir -p ./logs
RUN addgroup -S ${ROOT_USER}
RUN adduser -S ${ROOT_USER} -G ${ROOT_USER}
RUN chown ${ROOT_USER} ./logs
USER ${ROOT_USER}
COPY --from=builder /app/build/${PROJECT_NAME}/dependencies/ ./
COPY --from=builder /app/build/${PROJECT_NAME}/spring-boot-loader/ ./
COPY --from=builder /app/build/${PROJECT_NAME}/snapshot-dependencies/ ./
COPY --from=builder /app/build/${PROJECT_NAME}/application/ ./
ENTRYPOINT ["sh", "-c", "dumb-init java ${JAVA_OPTS} org.springframework.boot.loader.JarLauncher"]
