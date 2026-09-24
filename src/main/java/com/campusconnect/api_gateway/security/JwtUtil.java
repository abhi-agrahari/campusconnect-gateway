package com.campusconnect.api_gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public Claims validateAndExtractClaims(String token) {

        try {
            // extract claims
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            Date expiration = claims.getExpiration();

            if (expiration == null || expiration.before(new Date())) {
                log.warn("JWT token has expired");
                return null;
            }
            return claims;

        } catch (ExpiredJwtException e) {
            log.warn("JWT token has expired");

        } catch (SecurityException e) {
            log.warn("Invalid JWT signature: {}",
                    e.getMessage()
            );
        } catch (MalformedJwtException e) {
            log.warn("Malformed JWT token: {}",
                    e.getMessage()
            );
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token: {}",
                    e.getMessage()
            );

        } catch (IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}",
                    e.getMessage()
            );
        } catch (Exception e) {
            log.error("JWT validation error: {}",
                    e.getMessage()
            );
        }

        return null;
    }
}