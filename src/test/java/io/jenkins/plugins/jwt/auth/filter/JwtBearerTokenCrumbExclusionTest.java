package io.jenkins.plugins.jwt.auth.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.security.FullControlOnceLoggedInAuthorizationStrategy;
import hudson.security.csrf.CrumbExclusion;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Regression test for the interaction between {@link JwtBearerTokenCrumbExclusion} and another
 * {@link CrumbExclusion} that serves the request itself (as the mcp-server {@code Endpoint} does for
 * the MCP streamable endpoint).
 *
 * <p>Before the fix, {@link JwtBearerTokenCrumbExclusion} returned {@code false} without forwarding
 * the filter chain when a Bearer token was present but invalid/expired. The CSRF crumb filter then
 * handed the request to the next, lower-priority {@link CrumbExclusion}, which served it as the
 * anonymous user — so the RFC 6750 401 challenge from {@link ProtectedResourceChallengeFilter} was
 * never issued. This test reproduces that scenario with a competing request-consuming exclusion.
 */
@WithJenkins
class JwtBearerTokenCrumbExclusionTest {

    @Test
    void invalidBearerTokenIsChallengedAndNotConsumedByCompetingCrumbExclusion(JenkinsRule jenkinsRule)
            throws Exception {
        configure(jenkinsRule);

        // A structurally invalid token: rejected without any JWKS network access.
        HttpResponse<String> response = post(jenkinsRule.getURL() + "mcp-test/mcp", "not-a-valid-jwt");

        assertEquals(
                401,
                response.statusCode(),
                "An invalid Bearer token on a protected resource must be challenged with 401, "
                        + "not consumed by a competing CrumbExclusion. Body was: " + response.body());
        assertTrue(
                response.body().contains("invalid_token"),
                "Challenge body should signal invalid_token; body was: " + response.body());
        assertFalse(
                response.body().contains(ConsumingCrumbExclusion.MARKER),
                "The competing CrumbExclusion must not have handled the request; body was: " + response.body());
    }

    private void configure(JenkinsRule jenkinsRule) throws Exception {
        String basePath = jenkinsRule.getURL().getPath().replaceAll("/$", "");
        Issuer issuer = new Issuer("https://jwks.example.com/certs", "test-audience", basePath + "/mcp-test/**");

        ProtectedResourceMetadata protectedResource = new ProtectedResourceMetadata("/mcp-test/mcp");
        protectedResource.setAuthorizationServer("https://auth.example.com");
        protectedResource.setScopesSupportedValue("openid,profile");

        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        config.setIssuers(List.of(issuer));
        config.setProtectedResources(List.of(protectedResource));

        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        FullControlOnceLoggedInAuthorizationStrategy strategy = new FullControlOnceLoggedInAuthorizationStrategy();
        strategy.setAllowAnonymousRead(false);
        jenkinsRule.jenkins.setAuthorizationStrategy(strategy);
    }

    private HttpResponse<String> post(String url, String bearerToken) throws Exception {
        HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"));
        if (bearerToken != null) {
            requestBuilder.header("Authorization", "Bearer " + bearerToken);
        }
        return httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Mimics the mcp-server {@code Endpoint}: a {@link CrumbExclusion} that serves the request itself
     * (returning HTTP 200) instead of forwarding the chain. Its default ordinal (0) is lower than the
     * pinned ordinal of {@link JwtBearerTokenCrumbExclusion}, so it must never get the chance to
     * handle a Bearer-bearing request to the protected endpoint.
     */
    @TestExtension
    public static class ConsumingCrumbExclusion extends CrumbExclusion {

        static final String MARKER = "consumed-as-anonymous";

        @Override
        public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            String uri = request.getRequestURI();
            if (uri != null && uri.contains("/mcp-test/")) {
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().write("{\"status\":\"FAILED\",\"message\":\"" + MARKER + "\"}");
                response.getWriter().flush();
                return true;
            }
            return false;
        }
    }
}
