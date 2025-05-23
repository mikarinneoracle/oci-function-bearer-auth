package com.example.fn;

import com.fnproject.fn.api.FnConfiguration;
import com.fnproject.fn.api.InputEvent;
import com.fnproject.fn.api.RuntimeContext;
import com.fnproject.fn.api.httpgateway.HTTPGatewayContext;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.Base64;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import com.fasterxml.jackson.databind.ObjectMapper;

public class HelloFunction {

    private static String APP_URL       = "";
    private static String AUTH_URL      = "";
    private static String CLIENT_ID     = "";
    private static String CLIENT_SECRET = "";
    private static String IDCS_URL      = "";

    @FnConfiguration
    public void setUp(RuntimeContext ctx) throws Exception {
        APP_URL = ctx.getConfigurationByKey("APP_URL").orElse(System.getenv().getOrDefault("APP_URL", ""));
        AUTH_URL = ctx.getConfigurationByKey("AUTH_URL").orElse(System.getenv().getOrDefault("AUTH_URL", ""));
        CLIENT_ID = ctx.getConfigurationByKey("CLIENT_ID").orElse(System.getenv().getOrDefault("CLIENT_ID", ""));
        CLIENT_SECRET = ctx.getConfigurationByKey("CLIENT_SECRET").orElse(System.getenv().getOrDefault("CLIENT_SECRET", ""));
        IDCS_URL = ctx.getConfigurationByKey("IDCS_URL").orElse(System.getenv().getOrDefault("IDCS_URL", ""));
    }

    public String handleRequest(final HTTPGatewayContext hctx, final InputEvent input) {

        String userEmail = "";
        String ret       = "";

        System.out.println("==== FUNC ====");
        try {
            List<String> lines = Files.readAllLines(Paths.get("/func.yaml")).stream().limit(3).collect(Collectors.toList());
            lines.forEach(System.out::println);
            hctx.getHeaders().getAll().forEach((key, value) -> System.out.println(key + ": " + value));
            input.getHeaders().getAll().forEach((key, value) -> System.out.println(key + ": " + value));
            hctx.getQueryParameters().getAll().forEach((key, value) -> System.out.println(key + ": " + value));
        } catch (Exception e) {
            System.out.println("Error reading func.yaml: " + e.getMessage());
        }
        System.out.println("==============");

        String code = hctx.getQueryParameters().get("code").orElse(null);
        if(code != null)
        {
            try {
                String clientId = CLIENT_ID;
                String clientSecret = CLIENT_SECRET;
                String auth = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
                MultivaluedMap<String,String> formData = new MultivaluedHashMap<>();
                formData.add("grant_type", "authorization_code");
                formData.add("code", code);
                formData.add("client_id", clientId);

                Response tokenResponse = ClientBuilder.newClient()
                        .target("https://" + IDCS_URL + ".identity.oraclecloud.com:443/")
                        .path("oauth2/v1/token")
                        .request()
                        .header("Authorization", "Basic " + auth)
                        .header("Accept", "application/json")
                        .post(Entity.form(formData));

                //System.out.println("Status:" + tokenResponse.getStatus());
                //System.out.println("Status Info:" + tokenResponse.getStatusInfo());
                if(tokenResponse.getStatus() == 200)
                {
                    String accessToken = tokenResponse.readEntity(String.class);
                    userEmail = getEmail(accessToken);
                    hctx.setResponseHeader("Set-Cookie","Email=" + userEmail); // + "; HttpOnly");
                    String mainUrl = APP_URL;
                    hctx.setResponseHeader("Location", mainUrl);
                    hctx.setStatusCode(302);
                } else {
                    System.out.println("Access_token ERROR");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            String callbackUri = AUTH_URL;
            String clientId = CLIENT_ID;
            String idcsLoginUrl = "https://" + IDCS_URL + ".identity.oraclecloud.com:443/oauth2/v1/authorize?client_id=" + clientId + "&response_type=code&redirect_uri=" + callbackUri + "&scope=openid&state=1234";
            hctx.setResponseHeader("Location", idcsLoginUrl);
            hctx.setStatusCode(302);
            System.out.println("Redirect to " + idcsLoginUrl);
        }

        // This last part is for APIGW authorizer function
        // For APIGW just evaluate the Email cookie header and return response accordingly
        // Expects only 1 cookie set (Email)
        // Default denies access unless Email is found from Cookie
        boolean FOUND = false;
        String body = input.consumeBody((InputStream is) -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                return reader.lines().collect(Collectors.joining());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        System.out.println("Body: " + body);
        if(body.length() > 0) {
            String[] bodyTokens = body.split(",");
            List<String> tokenizedBody = Arrays.stream(bodyTokens).map(String::trim).collect(Collectors.toList());
            for (String token : tokenizedBody) {
                //System.out.println(token);
                if (token.indexOf("Email=") > -1) {
                    userEmail = token.substring(token.indexOf("Email=") + 6,  token.indexOf("\"}"));
                    System.out.println("userEmail : " + userEmail);
                    FOUND = true;
                }
            }
        }
        if(FOUND) {
            ret = "{ " +
                    "\"active\": true," +
                    "\"principal\": \"fnsimplejava\"," +
                    "\"scope\": [\"fnsimplejava\"]," +
                    "\"expiresAt\": \"2025-12-31T00:00:00+00:00\"," +
                    "\"context\": { \"Sub\": \"" + userEmail + "\" }" +
                    " }";
        } else {
            ret = "{ " +
                    "\"active\": false," +
                    "\"wwwAuthenticate\": \"Beare realm=\\\"" + APP_URL + "\\\"\"" +
                    " }";
        }
        System.out.println(ret);
        return ret;
    }

    private String getEmail(String jwtToken) {
        String email = null;
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String[] chunks = jwtToken.split("\\.");
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String payload = new String(decoder.decode(chunks[1]));
            JwtData jwtData = objectMapper.readValue(payload, JwtData.class);
            email = jwtData.sub;
        } catch (Exception e)
        {
            System.out.println("Email cannot be read from jwt, error:" + e.getMessage());
        }
        return email;
    }
}