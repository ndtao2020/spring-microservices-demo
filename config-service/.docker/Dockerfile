# --------------> The build image
FROM gradle:7-jdk17 AS builder

ARG PROJECT_NAME
ARG BUILD_FILE=./${PROJECT_NAME}/build/libs/app.jar

WORKDIR app
COPY . .
RUN gradle :${PROJECT_NAME}:clean :${PROJECT_NAME}:bootJar --info --stacktrace
RUN java -Djarmode=layertools -jar ${BUILD_FILE} extract --destination /app/build/${PROJECT_NAME}
RUN rm -f ${BUILD_FILE}

# --------------> The production image
FROM eclipse-temurin:17-jre-alpine

ARG PROJECT_NAME
ARG ROOT_USER=newuser
# ENV JAVA_TOOL_OPTIONS="-server -XX:+UseZGC -Xmx128m -agentlib:jdwp=transport=dt_socket,address=*:5005,server=y,suspend=n"

RUN apk update && apk add --no-cache dumb-init

WORKDIR /app

RUN addgroup -S ${ROOT_USER}
RUN adduser -S ${ROOT_USER} -G ${ROOT_USER}

USER ${ROOT_USER}

COPY --chown=${ROOT_USER}:root --from=builder /app/build/${PROJECT_NAME}/dependencies/ ./
COPY --chown=${ROOT_USER}:root --from=builder /app/build/${PROJECT_NAME}/spring-boot-loader/ ./
COPY --chown=${ROOT_USER}:root --from=builder /app/build/${PROJECT_NAME}/snapshot-dependencies/ ./
COPY --chown=${ROOT_USER}:root --from=builder /app/build/${PROJECT_NAME}/application/ ./
RUN mkdir -p ./logs
RUN chown ${ROOT_USER} ./logs

ENTRYPOINT ["sh", "-c", "dumb-init -- java org.springframework.boot.loader.JarLauncher"]
