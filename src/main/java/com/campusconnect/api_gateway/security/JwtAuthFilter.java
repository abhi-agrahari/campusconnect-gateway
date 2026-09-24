package com.campusconnect.api_gateway.security;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter implements GlobalFilter {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest()
                .getURI()
                .getPath();

        // public endpoints
        if (path.startsWith("/auth")
                || path.startsWith("/ws")
                || path.startsWith("/actuator")) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst("Authorization");

        // authorization header is required
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header for path: {}", path);

            exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);

            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7).trim();

        if (token.isEmpty()) {

            exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);

            return exchange.getResponse().setComplete();
        }

        try {

            // validate JWT and get claims
            Claims claims = jwtUtil.validateAndExtractClaims(token);
            if (claims == null) {
                log.warn("JWT validation failed for path: {}", path);

                exchange.getResponse()
                        .setStatusCode(HttpStatus.UNAUTHORIZED);

                return exchange.getResponse().setComplete();
            }

            String email = claims.getSubject();
            String role = claims.get("role", String.class);
            String collegeCode = claims.get("collegeCode", String.class);

            // admin authorization
            if (path.startsWith("/admin") && !"ADMIN".equalsIgnoreCase(role)) {
                log.warn("Forbidden access attempt to {} by role {}", path, role);

                exchange.getResponse()
                        .setStatusCode(HttpStatus.FORBIDDEN);

                return exchange.getResponse().setComplete();
            }

            // remove client-provided internal headers
            // add trusted values from JWT.
            exchange = exchange.mutate()
                    .request(request -> request.headers(headers -> {

                        headers.remove("X-USER-EMAIL");
                        headers.remove("X-USER-ROLE");
                        headers.remove("X-COLLEGE-CODE");

                        if (email != null) {
                            headers.add("X-USER-EMAIL", email);
                        }

                        if (role != null) {
                            headers.add("X-USER-ROLE", role);
                        }

                        if (collegeCode != null) {
                            headers.add("X-COLLEGE-CODE", collegeCode);
                        }
                    }))
                    .build();

        } catch (Exception e) {

            log.error("Authentication error for path {}: {}",
                    path,
                    e.getMessage()
            );

            exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);

            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }
}