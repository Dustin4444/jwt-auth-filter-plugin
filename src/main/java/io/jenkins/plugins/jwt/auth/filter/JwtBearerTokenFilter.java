package io.jenkins.plugins.jwt.auth.filter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import hudson.Extension;
import hudson.model.User;
import hudson.tasks.Mailer;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import jenkins.util.HttpServletFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * The request filter that validate JWT given as Bearer token
 */
@Extension(ordinal = 200)
public class JwtBearerTokenFilter implements HttpServletFilter {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(JwtBearerTokenFilter.class);

    public static final String BEARER_PREFIX = "Bearer ";
    private static final long DEFAULT_CLOCK_SKEW_SECONDS = 60;

    // JWKS Cache configuration
    private static final Duration JWKS_CACHE_EXPIRATION = Duration.ofMinutes(5);
    private static final Cache<String, JWKSet> JWKS_CACHE =
            Caffeine.newBuilder().expireAfterWrite(JWKS_CACHE_EXPIRATION).build();

    @Override
    public boolean handle(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
            throws IOException, ServletException {

        String requestURI = httpRequest.getRequestURI();

        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        if (!config.anyMatch(requestURI)) {
            LOG.trace("Request URI '{}' does not match any protected paths - skipping JWT filter", requestURI);
            return false;
        }

        // Check if this is an API request with Bearer token
        // If not, just continue the filters
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return false;
        }

        LOG.trace("Processing JWT Bearer token for: {}", requestURI);

        // Extract and validate JWT token
        String token = authHeader.substring(BEARER_PREFIX.length());
        boolean skipJwtValidation =
                Boolean.TRUE.equals(httpRequest.getAttribute(JwtBearerTokenCrumbExclusion.class.getName()));
        Authentication authentication = validateJwtToken(skipJwtValidation, token, requestURI);

        if (authentication != null) {

            // Set authentication context
            SecurityContextHolder.getContext().setAuthentication(authentication);
            LOG.info("JWT Bearer token authenticated user '{}' for path '{}'", authentication.getName(), requestURI);
            return false; // Continue filter chain
        }

        // Continue filters
        LOG.warn("JWT Bearer token validation failed - continuing with normal auth");
        return false;
    }

    /**
     * Verifies the signature of a signed JWT using JWKS from the specified issuer.
     */
    public static boolean verifyJwtSignature(SignedJWT signedJWT, Issuer issuer) {
        try {
            JWSHeader header = signedJWT.getHeader();
            String keyId = header.getKeyID();

            // Get the JWK
            JWK jwk = getJwkForVerification(keyId, issuer);
            if (jwk == null) {
                LOG.debug("No JWK found for key ID: {} from issuer: {}", keyId, issuer.getJwksUrl());
                return false;
            }

            // Reject expired token
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Date expirationTime = claimsSet.getExpirationTime();
            if (expirationTime != null && expirationTime.before(new Date())) {
                LOG.warn("JWT token has expired: {}", expirationTime);
                return false;
            }

            // Validate issued at time (with clock skew tolerance)
            Date issuedAt = claimsSet.getIssueTime();
            if (issuedAt != null) {
                long clockSkewMillis = DEFAULT_CLOCK_SKEW_SECONDS * 1000;
                Date now = new Date();
                if (issuedAt.getTime() > now.getTime() + clockSkewMillis) {
                    LOG.warn(
                            "JWT token issued in the future (allowed clock skew: {}s): {}",
                            DEFAULT_CLOCK_SKEW_SECONDS,
                            issuedAt);
                    return false;
                }
            }

            // Verify signature
            JWSVerifier verifier = createVerifier(jwk);
            return signedJWT.verify(verifier);

        } catch (Exception e) {
            LOG.warn("JWT signature verification error for issuer: " + issuer.getJwksUrl(), e);
            return false;
        }
    }

    /**
     * Gets the appropriate JWK for verification from JWKS of the specified issuer.
     */
    private static JWK getJwkForVerification(String keyId, Issuer issuer) {
        try {
            String jwksUrl = issuer.getJwksUrl();

            if (jwksUrl == null || jwksUrl.trim().isEmpty()) {
                LOG.warn("JWKS URL not configured for issuer. Please configure it in Jenkins Global Configuration.");
                return null;
            }

            JWKSet jwkSet = getJwks(jwksUrl);
            if (jwkSet == null) {
                LOG.warn("Failed to fetch JWKS from: {}", jwksUrl);
                return null;
            }
            LOG.debug(
                    "JWKS fetched successfully from {}, contains {} keys",
                    jwksUrl,
                    jwkSet.getKeys().size());

            // Find key by ID or use first available key
            JWK jwk = null;
            if (keyId != null) {
                LOG.debug("Looking for key with ID: {}", keyId);
                jwk = jwkSet.getKeyByKeyId(keyId);
                if (jwk != null) {
                    LOG.debug("Found key with matching ID: {}", keyId);
                } else {
                    LOG.debug("No key found with ID: {}", keyId);
                }
            }

            if (jwk == null && !jwkSet.getKeys().isEmpty()) {
                // If no key ID specified or key not found, try the first key
                jwk = jwkSet.getKeys().get(0);
                LOG.debug("Using first available JWK for verification");
            }

            return jwk;

        } catch (Exception e) {
            LOG.warn("Failed to get JWK for verification from issuer: " + issuer.getJwksUrl(), e);
            return null;
        }
    }

    /**
     * Gets the JWK set with caching support (5-minute TTL)
     */
    private static JWKSet getJwks(String url) {
        try {
            LOG.debug("Getting JWKS from cache or fetching from: {}", url);
            return JWKS_CACHE.get(url, jwksUrl -> {
                try {
                    LOG.info("Cache miss - fetching JWKS from: {}", jwksUrl);
                    JWKSet jwkSet = JWKSet.load(new URL(jwksUrl));
                    if (jwkSet != null && !jwkSet.getKeys().isEmpty()) {
                        return jwkSet;
                    }
                    LOG.warn("JWKS endpoint returned empty key set: {}", jwksUrl);
                    return null;
                } catch (IOException | ParseException e) {
                    LOG.warn("Failed to fetch JWKS from: {}", jwksUrl, e);
                    return null;
                }
            });
        } catch (Exception e) {
            LOG.warn("Error accessing JWKS cache for URL: {}", url, e);
            return null;
        }
    }

    /**
     * Creates appropriate JWS verifier based on key type and algorithm.
     */
    private static JWSVerifier createVerifier(JWK jwk) throws JOSEException {
        if (jwk instanceof RSAKey rsaKey) {
            RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
            return new RSASSAVerifier(publicKey);
        } else if (jwk instanceof ECKey ecKey) {
            ECPublicKey publicKey = ecKey.toECPublicKey();
            return new ECDSAVerifier(publicKey);

        } else if (jwk instanceof OctetSequenceKey hsKey) {
            byte[] secretKey = hsKey.toByteArray();
            return new MACVerifier(secretKey);

        } else {
            LOG.debug("Unsupported JWK type: {}", jwk.getClass().getName());
            throw new IllegalArgumentException(
                    "Unsupported JWK type: " + jwk.getClass().getName());
        }
    }

    /**
     * Validates JWT token and returns Authentication object if valid.
     * Tries each issuer that matches the request path until one validates successfully.
     */
    private Authentication validateJwtToken(boolean skipJwtValidation, String tokenString, String requestURI) {
        try {
            LOG.debug("Starting JWT token validation for URI: {}", requestURI);

            // Parse JWT token once
            SignedJWT signedJWT = SignedJWT.parse(tokenString);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            LOG.debug(
                    "JWT parsed successfully. Subject: {}, Issuer: {}", claimsSet.getSubject(), claimsSet.getIssuer());

            // Get configuration
            JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
            if (config == null) {
                LOG.warn("JWT Bearer Token configuration not available");
                return null;
            }

            // Get all issuers that match the request path
            List<Issuer> matchingIssuers = config.getIssuers().stream()
                    .filter(issuer -> issuer.matchesPath(requestURI))
                    .toList();

            if (matchingIssuers.isEmpty()) {
                LOG.warn("No issuers match the request path: {}", requestURI);
                return null;
            }

            // Try each matching issuer until one validates successfully
            for (Issuer issuer : matchingIssuers) {
                LOG.debug(
                        "Trying issuer with JWKS URL: {} and audience: {}",
                        issuer.getJwksUrl(),
                        issuer.getAllowedAudience());

                // Validate claims (expiration, audience, issuer) for this issuer
                if (!validateTokenClaims(claimsSet, issuer)) {
                    LOG.warn("JWT token claims validation failed for issuer: {}", issuer.getJwksUrl());
                    continue; // Try next issuer
                }

                if (skipJwtValidation) {
                    LOG.info("Skipping JWT signature validation due to request attribute from crumb");
                } else {
                    LOG.info("Performing JWT signature validation for issuer: {}", issuer.getJwksUrl());
                    // Validate token signature for this issuer
                    if (!verifyJwtSignature(signedJWT, issuer)) {
                        LOG.warn("JWT token signature validation failed for issuer: {}", issuer.getJwksUrl());
                        continue; // Try next issuer
                    }
                }

                // This issuer validated successfully
                LOG.info("JWT token validated successfully with issuer: {}", issuer.getJwksUrl());

                // Extract user information
                String username = extractUsername(claimsSet, issuer);
                if (username == null || username.isEmpty()) {
                    LOG.warn("Unable to extract username from JWT token");
                    continue; // Try next issuer
                }
                String name = extractName(claimsSet, issuer);
                String email = extractEmail(claimsSet, issuer);

                // Extract authorities/groups
                Collection<GrantedAuthority> authorities = extractAuthorities(claimsSet, issuer);
                LOG.debug("Extracted username: {} with {} authorities", username, authorities.size());

                // Create or update Jenkins user
                ensureUserExists(username, name, email);

                LOG.debug(
                        "JWT validation completed successfully for user: {} with issuer: {}",
                        username,
                        issuer.getJwksUrl());
                return new JwtBearerTokenAuthentication(username, authorities);
            }

            LOG.debug("JWT token validation failed for all matching issuers");
            return null;

        } catch (ParseException e) {
            LOG.warn("Failed to parse JWT token", e);
            return null;
        } catch (Exception e) {
            LOG.warn("JWT token validation error", e);
            return null;
        }
    }

    /**
     * Validates JWT token claims (audience, etc.) for the specified issuer.
     */
    private boolean validateTokenClaims(JWTClaimsSet claimsSet, Issuer issuer) {
        try {

            // Validate audience
            String expectedAudience = issuer.getAllowedAudience();

            if (expectedAudience == null || expectedAudience.trim().isEmpty()) {
                LOG.warn(
                        "Allowed audience not configured for issuer: {}. Audience validation will be skipped. Configure an audience in Jenkins Global Configuration to restrict tokens to this resource server.",
                        issuer.getJwksUrl());
                return true;
            }

            List<String> audiences = claimsSet.getAudience();
            if (audiences == null || !audiences.contains(expectedAudience)) {
                LOG.warn(
                        "JWT token audience validation failed for issuer: {} - Expected: {}, Found: {}",
                        issuer.getJwksUrl(),
                        expectedAudience,
                        audiences);
                return false;
            }
            return true;

        } catch (Exception e) {
            LOG.warn("JWT claims validation failed with exception for issuer: " + issuer.getJwksUrl(), e);
            return false;
        }
    }

    /**
     * Extracts username from JWT claims using configured claim name.
     */
    private String extractUsername(JWTClaimsSet claimsSet, Issuer issuer) {
        try {
            Object username = claimsSet.getClaim(issuer.getEffectiveUsernameClaim());
            return username != null ? username.toString() : null;
        } catch (Exception e) {
            LOG.debug("Failed to extract {} from JWT", issuer.getEffectiveUsernameClaim(), e);
            return null;
        }
    }

    /**
     * Extracts email from JWT claims using configured claim name.
     */
    private String extractEmail(JWTClaimsSet claimsSet, Issuer issuer) {
        try {
            Object email = claimsSet.getClaim(issuer.getEffectiveEmailClaim());
            return email != null ? email.toString() : null;
        } catch (Exception e) {
            LOG.debug("Failed to extract {} from JWT", issuer.getEffectiveEmailClaim(), e);
            return null;
        }
    }

    /**
     * Extracts name from JWT claims using configured claim name.
     */
    private String extractName(JWTClaimsSet claimsSet, Issuer issuer) {
        try {
            Object nameValue = claimsSet.getClaim(issuer.getEffectiveNameClaim());
            return nameValue != null ? nameValue.toString() : null;
        } catch (Exception e) {
            LOG.debug("Failed to extract {} from JWT", issuer.getEffectiveNameClaim(), e);
            return null;
        }
    }

    /**
     * Extracts authorities/groups from JWT claims using configured claim name.
     */
    private Collection<GrantedAuthority> extractAuthorities(JWTClaimsSet claimsSet, Issuer issuer) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        try {
            // Get groups
            Object groupsClaim = claimsSet.getClaim(issuer.getEffectiveGroupsClaim());
            @SuppressWarnings("unchecked")
            List<String> groups = (List<String>) groupsClaim;
            authorities.addAll(groups.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));

            // Always add authenticated authority
            authorities.add(new SimpleGrantedAuthority("authenticated"));

        } catch (Exception e) {
            LOG.debug("Failed to extract authorities from JWT", e);
        }

        return authorities;
    }

    /**
     * Ensures the user exists in Jenkins user database.
     */
    private void ensureUserExists(String username, String name, String email) {
        try {
            User user = User.getById(username, true);
            if (user != null) {
                updateUserProperties(user, name, email);
            }
        } catch (Exception e) {
            LOG.debug("Failed to create/update user: {}", username, e);
        }
    }

    /**
     * Updates user properties from JWT claims.
     */
    private void updateUserProperties(User user, String name, String email) {
        try {
            if (email != null && !email.trim().isEmpty()) {
                user.addProperty(new Mailer.UserProperty(email));
            }
            if (name != null && !name.trim().isEmpty()) {
                user.setFullName(name);
            }
            user.save();
        } catch (Exception e) {
            LOG.debug("Failed to update user properties", e);
        }
    }
}
