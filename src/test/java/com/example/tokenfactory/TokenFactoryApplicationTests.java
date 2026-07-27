package com.example.tokenfactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class TokenFactoryApplicationTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper json;

    @Autowired
    TokenFactory tokenFactory;

    @Test
    void printsTheTokenBeforeAndAfterEncryption() throws Exception {
        TokenFactory.Nested token = tokenFactory.createNestedToken("alice");
        String[] parts = token.signed().split("\\.");

        System.out.println("\n--- JWT before encryption (signed JWS, 3 parts) ---");
        System.out.println(token.signed());
        System.out.println("\n  decoded header:  " + decode(parts[0]));
        System.out.println("  decoded claims:  " + decode(parts[1]));
        System.out.println("\n--- JWT after encryption (nested JWE, 5 parts, contents are opaque) ---");
        System.out.println(token.encrypted() + "\n");

        assertThat(parts).hasSize(3);
        assertThat(token.encrypted().split("\\.")).hasSize(5);
    }

    /** Base64url-decodes one part of a JWS and pretty-prints the JSON it contains. */
    private String decode(String jwsPart) throws Exception {
        String jsonText = new String(Base64.getUrlDecoder().decode(jwsPart), StandardCharsets.UTF_8);
        return json.writerWithDefaultPrettyPrinter().writeValueAsString(json.readTree(jsonText))
                .replace("\n", "\n                   "); // indent under the label
    }

    private MvcResult issue(String user) throws Exception {
        return mvc.perform(post("/tokens").param("user", user))
                .andExpect(status().isOk())
                .andExpect(cookie().exists(Cookies.ACCESS_TOKEN))
                .andExpect(cookie().exists(Cookies.REFRESH_TOKEN))
                .andReturn();
    }

    @Test
    void tokenCarriesClientIdAndTwoSixDigitAccounts() throws Exception {
        Cookie accessToken = issue("alice").getResponse().getCookie(Cookies.ACCESS_TOKEN);

        String body = mvc.perform(get("/me").cookie(accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user").value("alice"))
                .andExpect(jsonPath("$.accounts.length()").value(2))
                .andReturn().getResponse().getContentAsString();

        for (JsonNode account : json.readTree(body).get("accounts")) {
            assertThat(account.get("accountId").asText()).matches("\\d{6}");
        }
    }

    @Test
    void missingAccessTokenRedirectsToRefresh() throws Exception {
        mvc.perform(get("/me"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "/refresh?redirect=%2Fme"));
    }

    @Test
    void refreshTokenMintsANewAccessTokenAndRedirectsBack() throws Exception {
        Cookie refreshToken = issue("bob").getResponse().getCookie(Cookies.REFRESH_TOKEN);

        // Follow the refresh the way an expired client would: only the refresh cookie is sent.
        MvcResult refreshed = mvc.perform(get("/refresh").param("redirect", "/me").cookie(refreshToken))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "/me"))
                .andExpect(cookie().exists(Cookies.ACCESS_TOKEN))
                .andReturn();

        // The freshly minted access token works on the protected endpoint.
        mvc.perform(get("/me").cookie(refreshed.getResponse().getCookie(Cookies.ACCESS_TOKEN)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user").value("bob"));
    }

    @Test
    void refreshWithoutARefreshTokenIsUnauthorized() throws Exception {
        mvc.perform(get("/refresh")).andExpect(status().isUnauthorized());
    }
}
