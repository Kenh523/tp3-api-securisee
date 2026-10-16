package com.tp3.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class RateLimitTest {

    @Autowired MockMvc mvc;

    @Test
    void la_6e_tentative_de_login_est_bloquee_en_429() throws Exception {
        for (int i = 1; i <= 5; i++) {
            mvc.perform(attempt()).andExpect(status().isUnauthorized());
        }
        mvc.perform(attempt())
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder attempt() {
        return post("/auth/login").with(r -> { r.setRemoteAddr("10.9.9.9"); return r; })
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"mauvais\"}");
    }
}
