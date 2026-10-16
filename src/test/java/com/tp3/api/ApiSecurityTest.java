package com.tp3.api;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.tp3.api.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.web.servlet.MockMvc;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ApiSecurityTest {

    private static final String AUTH = "Authorization";
    private static final String NOTE_JSON = "{\"title\":\"titre\",\"content\":\"contenu\"}";

    @Autowired MockMvc mvc;
    @Autowired JwtService jwtService;
    @Autowired JwtEncoder encoder;
    @Value("${app.jwt.issuer}") String issuer;
    @Value("${app.jwt.audience}") String audience;
    @Value("${app.demo.password}") String demoPassword;

    private String bearer(String user, String... roles) {
        return "Bearer " + jwtService.issue(user, List.of(roles));
    }

    private String customToken(JwtEncoder enc, String iss, String aud, Instant exp) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(iss).audience(List.of(aud)).subject("alice")
                .issuedAt(exp.minus(15, ChronoUnit.MINUTES)).expiresAt(exp)
                .claim("roles", List.of("USER")).build();
        return "Bearer " + enc.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
    }

    private long createNote(String auth) throws Exception {
        String body = mvc.perform(post("/notes").header(AUTH, auth)
                        .contentType(MediaType.APPLICATION_JSON).content(NOTE_JSON))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return ((Number) JsonPath.read(body, "$.id")).longValue();
    }

    // ---- 401 / 403 / BOLA : les 3 cas exiges par le TP ----

    @Test
    void anonyme_recoit_401() throws Exception {
        mvc.perform(get("/notes")).andExpect(status().isUnauthorized());
    }

    @Test
    void utilisateur_sans_droit_recoit_403() throws Exception {
        long id = createNote(bearer("alice", "USER"));
        mvc.perform(delete("/notes/" + id).header(AUTH, bearer("alice", "USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void utilisateur_ne_peut_pas_lire_lobjet_dun_autre_BOLA() throws Exception {
        long id = createNote(bearer("alice", "USER"));
        mvc.perform(get("/notes/" + id).header(AUTH, bearer("bob", "USER")))
                .andExpect(status().isForbidden());
        mvc.perform(put("/notes/" + id).header(AUTH, bearer("bob", "USER"))
                        .contentType(MediaType.APPLICATION_JSON).content(NOTE_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    void proprietaire_lit_sa_note_sans_voir_le_champ_owner() throws Exception {
        long id = createNote(bearer("alice", "USER"));
        mvc.perform(get("/notes/" + id).header(AUTH, bearer("alice", "USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("titre"))
                .andExpect(jsonPath("$.owner").doesNotExist());
    }

    @Test
    void admin_peut_supprimer() throws Exception {
        long id = createNote(bearer("alice", "USER"));
        mvc.perform(delete("/notes/" + id).header(AUTH, bearer("admin", "ADMIN")))
                .andExpect(status().isNoContent());
    }

    // ---- Validation des jetons JWT ----

    @Test
    void jeton_expire_refuse() throws Exception {
        String t = customToken(encoder, issuer, audience, Instant.now().minus(10, ChronoUnit.MINUTES));
        mvc.perform(get("/notes").header(AUTH, t)).andExpect(status().isUnauthorized());
    }

    @Test
    void mauvais_emetteur_refuse() throws Exception {
        String t = customToken(encoder, "https://pirate.example", audience, Instant.now().plus(5, ChronoUnit.MINUTES));
        mvc.perform(get("/notes").header(AUTH, t)).andExpect(status().isUnauthorized());
    }

    @Test
    void mauvaise_audience_refusee() throws Exception {
        String t = customToken(encoder, issuer, "autre-api", Instant.now().plus(5, ChronoUnit.MINUTES));
        mvc.perform(get("/notes").header(AUTH, t)).andExpect(status().isUnauthorized());
    }

    @Test
    void mauvaise_signature_refusee() throws Exception {
        JwtEncoder pirate = new NimbusJwtEncoder(new ImmutableSecret<>(new SecretKeySpec(
                "un-autre-secret-un-autre-secret-123456".getBytes(StandardCharsets.UTF_8), "HmacSHA256")));
        String t = customToken(pirate, issuer, audience, Instant.now().plus(5, ChronoUnit.MINUTES));
        mvc.perform(get("/notes").header(AUTH, t)).andExpect(status().isUnauthorized());
    }

    // ---- DTO + validation ----

    @Test
    void titre_vide_donne_400() throws Exception {
        mvc.perform(post("/notes").header(AUTH, bearer("alice", "USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"\",\"content\":\"x\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void mass_assignment_ignore_owner_fourni_par_le_client() throws Exception {
        long id = ((Number) JsonPath.read(mvc.perform(post("/notes").header(AUTH, bearer("alice", "USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"t\",\"content\":\"c\",\"owner\":\"bob\"}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString(), "$.id")).longValue();
        // si owner=bob avait ete pris en compte, alice recevrait 403 ici
        mvc.perform(get("/notes/" + id).header(AUTH, bearer("alice", "USER"))).andExpect(status().isOk());
    }

    // ---- Login ----

    @Test
    void login_valide_donne_un_jeton() throws Exception {
        mvc.perform(post("/auth/login").with(r -> { r.setRemoteAddr("10.1.1.1"); return r; })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"" + demoPassword + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());
    }

    @Test
    void login_invalide_donne_401() throws Exception {
        mvc.perform(post("/auth/login").with(r -> { r.setRemoteAddr("10.1.1.2"); return r; })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"faux\"}"))
                .andExpect(status().isUnauthorized());
    }
}
