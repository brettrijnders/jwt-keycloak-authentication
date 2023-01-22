package com.beesar;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class Main {
    static Logger logger = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        // Configure keycloak first in order to be able to get tokens: https://cloudnativereference.dev/related-repositories/keycloak/ and
        // https://developers.redhat.com/blog/2020/01/29/api-login-and-jwt-token-generation-using-keycloak#test_your_new_client

        // For getting the token see https://developers.redhat.com/blog/2020/01/29/api-login-and-jwt-token-generation-using-keycloak#test_your_new_client

        long totalStart = System.currentTimeMillis();
        HashMap<String, String> params = new HashMap<>();
        params.put("client_secret", ""); // Enter client secret configured in Keycloak
        params.put("client_id", ""); // Enter client id configured in Keycloak
        params.put("username", ""); // Enter username configured in Keycloak
        params.put("password", ""); // Enter user password configured in Keycloak
        params.put("grant_type", "password");
        params.put("scope", "openid");

        HttpResponse<String> response = getTokenResponse(params);

        if (response != null && response.statusCode() == 200) {
            logger.info(() -> "Valid response!");
            JSONObject jsonResp = new JSONObject(response.body());
            String accessToken = jsonResp.getString("access_token");
            logger.info(() -> String.format("Using token: %s", accessToken));
            final JwtValidator validator = new JwtValidator(true);
            try {
                long valStart = System.currentTimeMillis();
                DecodedJWT token = validator.validate(accessToken);
                long valEnd = System.currentTimeMillis();
                logger.info(() -> String.format("Validation took %s ms", (valEnd - valStart)));

                long totalEnd = System.currentTimeMillis();
                logger.info(() -> String.format("Login took %s ms", (totalEnd - totalStart)));

                for (int i = 0; i < 1000; i++) {
                    logger.info(() -> "Using cached public key");
                    validate(accessToken, validator);
                }

                logger.info(() -> "Waiting for 1 minute so that it will need to refresh public key in cache");
                try {
                    Thread.sleep(1000 * 60);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }

                logger.info(() -> "Using refreshed public key");
                validate(accessToken, validator);

            } catch (InvalidParameterException e) {
                logger.log(Level.SEVERE, () -> "Jwt is invalid!");
                e.printStackTrace();
            }
        } else {
            logger.severe(String.format("Failed to retrieve access token (status code:%s): %s", response.statusCode(), response.body()));
        }
    }

    private static HttpResponse<String> getTokenResponse(HashMap<String, String> params) {
        String form = params.entrySet().stream().map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&"));

        HttpClient client = HttpClient.newHttpClient();
        // For token endpoint see: http://IP_KEYCLOAK:PORT/realms/myrealm/.well-known/openid-configuration
        //  Use local hosted Keycloak service
        String tokenEndpoint = "http://localhost:8080/realms/myrealm/protocol/openid-connect/token";
        HttpRequest request = null;
        HttpResponse<String> response = null;
        try {
            request = HttpRequest.newBuilder()
                    .uri(new URI(tokenEndpoint))
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .headers("Content-Type", "application/x-www-form-urlencoded")
                    .build();
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        return response;
    }

    private static void validate(String accessToken, JwtValidator validator) {
        DecodedJWT token;
        long valStart2 = System.currentTimeMillis();
        token = validator.validate(accessToken);
        long valEnd2 = System.currentTimeMillis();
        logger.log(Level.INFO, () -> "Jwt is valid!");
        logger.info(() -> String.format("Validation took %s ms", (valEnd2 - valStart2)));
    }
}