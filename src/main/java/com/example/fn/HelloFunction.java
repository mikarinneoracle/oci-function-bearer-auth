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
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
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
import java.util.Random;
import java.time.LocalDateTime;

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

        String BEARER = "";
        String ret       = "";

        System.out.println("==== FUNC ====");
        try {
            List<String> lines = Files.readAllLines(Paths.get("/func.yaml")).stream().limit(3).collect(Collectors.toList());
            lines.forEach(System.out::println);
            //hctx.getHeaders().getAll().forEach((key, value) -> System.out.println(key + ": " + value));
            //input.getHeaders().getAll().forEach((key, value) -> System.out.println(key + ": " + value));
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
                    ObjectMapper objectMapper = new ObjectMapper();
                    String[] chunks = accessToken.split("\\.");
                    String token = chunks[1];
                    hctx.setResponseHeader("Set-Cookie","bearer=" + token); // + "; HttpOnly");
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
            Random rand = new Random();
            int randomState = rand.nextInt(10000) + 1;
            String idcsLoginUrl = "https://" + IDCS_URL + ".identity.oraclecloud.com:443/oauth2/v1/authorize?client_id=" + clientId + "&response_type=code&redirect_uri=" + callbackUri + "&scope=openid&state=" + randomState;
            hctx.setResponseHeader("Location", idcsLoginUrl);
            hctx.setStatusCode(302);
            System.out.println("Redirect to " + idcsLoginUrl);
        }

        // This last part is for APIGW authorizer function
        // For APIGW just evaluate the bearer cookie header and return response accordingly
        // Expects only 1 cookie set (bearer)
        // Default denies access unless bearer is found from Cookie
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
                if (token.indexOf("bearer=") > -1) {
                    BEARER = token.substring(token.indexOf("bearer=") + 7,  token.indexOf("\"}"));
                    System.out.println("BEARER : " + BEARER);
                    FOUND = true;
                }
            }
        }
        if(FOUND) {
            LocalDateTime dateTime = LocalDateTime.now().plusDays(1);
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'+00:00'");
            String expiryDate = dateTime.format(formatter);
            ret = "{ " +
                    "\"active\": true," +
                    "\"principal\": \"fnsimplejava\"," +
                    "\"scope\": [\"fnsimplejava\"]," +
                    "\"expiresAt\": \"" + expiryDate + "\"," +
                    "\"context\": { \"Sub\": \"" + BEARER + "\" }" +
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
}