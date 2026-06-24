package io.jenkins.plugins.jwt.auth.filter;

import com.nimbusds.jwt.SignedJWT;
import hudson.Extension;
import hudson.security.csrf.CrumbExclusion;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A JWT bearer token that exclude requested from Crumb that contains a valid signed JWT token.
 *
 * <p>This exclusion is pinned to a high ordinal so that it runs before other {@link CrumbExclusion}s
 * that may consume the request themselves (most notably the mcp-server {@code Endpoint}, which serves
 * the MCP streamable endpoint directly from its {@code process()} method). If a competing exclusion
 * ran first and handled a request carrying an invalid/expired Bearer token, the request would be
 * processed as anonymous and the RFC 6750 401 challenge issued by
 * {@link ProtectedResourceChallengeFilter} would be bypassed.
 */
@Extension(ordinal = 1000)
public class JwtBearerTokenCrumbExclusion extends CrumbExclusion {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(JwtBearerTokenCrumbExclusion.class);

    @Override
    public boolean process(HttpServletRequest httpRequest, HttpServletResponse httpResponse, FilterChain chain)
            throws IOException, ServletException {

        // Skip if not on configured path
        String requestURI = httpRequest.getRequestURI();
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        if (!config.anyMatch(requestURI)) {
            LOG.trace(
                    "Request URI '{}' does not match any protected paths - skipping JWT Bearer Crumb filter",
                    requestURI);
            return false;
        }

        // Skip if header is missing
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith(JwtBearerTokenFilter.BEARER_PREFIX)) {
            chain.doFilter(httpRequest, httpResponse);
            return false;
        }

        // A Bearer token is present on a protected path. Determine whether it validates against any
        // matching issuer so that valid requests can be excluded from the CSRF crumb check.
        String tokenString = authHeader.substring(JwtBearerTokenFilter.BEARER_PREFIX.length());
        boolean validToken = false;
        try {
            SignedJWT signedJWT = SignedJWT.parse(tokenString);

            // Get all issuers that match the request path
            for (Issuer issuer : config.getIssuers()) {
                if (issuer.matchesPath(requestURI) && JwtBearerTokenFilter.verifyJwtSignature(signedJWT, issuer)) {
                    LOG.info(
                            "Valid JWT token found in request for issuer {}, excluding from Crumb",
                            issuer.getJwksUrl());
                    validToken = true;
                    break;
                }
            }
        } catch (Exception e) {
            LOG.warn("Failed to parse or verify JWT token from Authorization header", e);
        }

        if (validToken) {
            httpRequest.setAttribute(JwtBearerTokenCrumbExclusion.class.getName(), Boolean.TRUE);
        }

        // Always drive the remaining filter chain ourselves for a Bearer-bearing request on a
        // protected path, regardless of token validity. API clients authenticating via a Bearer
        // token never carry a Jenkins CSRF crumb, so the crumb check is irrelevant for them. More
        // importantly, this guarantees the request reaches the HttpServletFilter phase
        // (JwtBearerTokenFilter + ProtectedResourceChallengeFilter) instead of being consumed by a
        // lower-priority CrumbExclusion (e.g. the mcp-server Endpoint) that would serve it as
        // anonymous and bypass the RFC 6750 401 challenge for invalid/expired tokens.
        chain.doFilter(httpRequest, httpResponse);
        return true;
    }
}
