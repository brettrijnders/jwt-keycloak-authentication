package com.beesar;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidParameterException;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Jwt validator class.
 * <p>
 * This class was based on what was explained in this video:
 * https://www.youtube.com/watch?v=Dr4Ae61KGsM
 * <p>
 * The original source code that was used in that video can be found here:
 * https://github.com/ps-after-hours/jwt-validator/blob/main/jwt-validation/src/main/java/com/quadmeup/JwtValidator.java
 */
public class JwtValidator {
    static Logger logger = Logger.getLogger(JwtValidator.class.getName());
    private static final List<String> allowedIsses = Collections.singletonList("http://localhost:8080/realms/myrealm");
    private LoadingCache<DecodedJWTKey, RSAPublicKey> fCache = null;
    private RSAPublicKey fPublicKey = null;
    private boolean useCache = false;

    public JwtValidator(boolean enableCache) {
        useCache = enableCache;
        if (enableCache) {
            initCache();
        }
    }

    private void initCache() {
        CacheLoader<DecodedJWTKey, RSAPublicKey> loader = new CacheLoader<>() {
            @Override
            public RSAPublicKey load(DecodedJWTKey jtwWrapper) throws Exception {
                return loadPublicKey(jtwWrapper);
            }
        };

        fCache = CacheBuilder.newBuilder().refreshAfterWrite(1, TimeUnit.MINUTES).build(loader);
    }

    private String getKeycloakCertificateUrl(DecodedJWT token) {
        return token.getIssuer() + "/protocol/openid-connect/certs";
    }

    private RSAPublicKey loadPublicKey(DecodedJWTKey jwtKey) throws JwkException, MalformedURLException {
        final String keycloakCertificateUrl = jwtKey.getCertUrl();
        final DecodedJWT token = jwtKey.getJwt();
        JwkProvider provider = new UrlJwkProvider(new URL(keycloakCertificateUrl));
        return (RSAPublicKey) provider.get(token.getKeyId()).getPublicKey();
    }

    public void refreshPublicKeyForToken(String token) {
        final DecodedJWT jwt = JWT.decode(token);
        if (!allowedIsses.contains(jwt.getIssuer())) {
            throw new InvalidParameterException(String.format("Unknown Issuer %s", jwt.getIssuer()));
        }
        DecodedJWTKey decodedJWTKey = new DecodedJWTKey(jwt);

        fCache.refresh(decodedJWTKey);
    }

    /**
     * Validate a JWT token
     *
     * @param token
     * @return decoded token
     */
    public DecodedJWT validate(String token) {
        try {
            final DecodedJWT jwt = JWT.decode(token);

            if (!allowedIsses.contains(jwt.getIssuer())) {
                throw new InvalidParameterException(String.format("Unknown Issuer %s", jwt.getIssuer()));
            }

            DecodedJWTKey decodedJWTKey = new DecodedJWTKey(jwt);
            if (useCache) {
                fPublicKey = fCache.get(decodedJWTKey);
            } else {
                fPublicKey = loadPublicKey(decodedJWTKey);
            }

            Algorithm algorithm = Algorithm.RSA256(fPublicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(jwt.getIssuer())
                    .build();

            verifier.verify(token);
            return jwt;

        } catch (Exception e) {
            logger.log(Level.SEVERE, e, () -> "Failed to validate JWT");
            throw new InvalidParameterException("JWT validation failed: " + e.getMessage());
        }
    }

    private class DecodedJWTKey {
        private final DecodedJWT fJwt;
        private final String fUrl;

        public DecodedJWTKey(DecodedJWT jwt) {
            fJwt = jwt;
            fUrl = getKeycloakCertificateUrl(jwt);
        }

        public DecodedJWT getJwt() {
            return fJwt;
        }

        public String getCertUrl() {
            return fUrl;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            DecodedJWTKey that = (DecodedJWTKey) o;
            return getCertUrl().equals(that.getCertUrl());
        }

        @Override
        public int hashCode() {
            return Objects.hash(getCertUrl());
        }
    }
}
