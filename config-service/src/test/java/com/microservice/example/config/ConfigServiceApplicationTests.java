package com.microservice.example.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ConfigServiceApplicationTests {

    private static final String USER = "admin";
    private static final String PASSWORD = "12345678";

    @Autowired
    MockMvc mockMvc;
    @Autowired
    TestRestTemplate restTemplate;

    @Test
    void contextLoads(@Value(value = "${local.server.port}") int port) {
        assertThat(this.restTemplate.getForObject("http://localhost:" + port + "/", String.class)).isNullOrEmpty();
    }

    @Test
    void shouldReturnDefaultMessage() throws Exception {
        this.mockMvc
                .perform(get("/discovery-service/default"))
                .andDo(print())
                .andExpect(status().is4xxClientError());
    }

    @Test
    @WithAnonymousUser
    void shouldReturnError_AnonymousUser() throws Exception {
        this.mockMvc
                .perform(get("/discovery-service/default"))
                .andDo(print())
                .andExpect(status().is4xxClientError());
    }

    @Test
    void shouldReturnError_AnonymousUser_2() throws Exception {
        this.mockMvc
                .perform(get("/discovery-service/default").with(anonymous()))
                .andDo(print())
                .andExpect(status().is4xxClientError());
    }

    @Test
    @WithAnonymousUser
    void shouldReturnOK_AnonymousUser() throws Exception {
        this.mockMvc
                .perform(get("/discovery-service/default").with(anonymous()))
                .andDo(print())
                .andExpect(status().is4xxClientError());
    }

    @Test
    @WithMockUser(username = USER, password = PASSWORD, roles = {"USER", "ADMIN"})
    void shouldReturnStatusOK_Role() throws Exception {
        this.mockMvc
                .perform(get("/discovery-service/default").with(user(USER).password(PASSWORD).roles("USER", "ADMIN")))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE));
    }

    @Test
    @WithMockUser(username = USER, password = PASSWORD)
    void shouldReturnStatusOK_BasicAuthentication() throws Exception {
        this.mockMvc
                .perform(get("/discovery-service/default").with(httpBasic(USER, PASSWORD)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE));
    }
}
