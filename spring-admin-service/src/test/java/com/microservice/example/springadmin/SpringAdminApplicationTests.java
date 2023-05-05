package com.microservice.example.springadmin;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(
        // Normally spring.cloud.config.enabled:true is the default but since we have the
        // config server on the classpath we need to set it explicitly
        properties = {
                "spring.cloud.config.enabled:true",
                "spring.config.use-legacy-processing=true",
                "management.security.enabled=false",
                "management.endpoints.web.exposure.include=*",
                "management.endpoint.env.show-values=ALWAYS"
        },
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
class SpringAdminApplicationTests {

    @Test
    void contextLoads() {
    }

}
