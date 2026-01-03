package com.campusconnect.api_gateway.security;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter implements GlobalFilter {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst("Authorization");

        if(exchange.getRequest().getURI().getPath().startsWith("/auth")){
            return chain.filter(exchange);
        }

        if(authHeader == null ||!authHeader.startsWith("Bearer ")){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        try{
            String token = authHeader.substring(7);
            Claims claims = jwtUtil.extractClaims(token);

            exchange = exchange.mutate()
                    .request(r -> r.headers(headers -> {
                        headers.add("X-USER-EMAIL", claims.getSubject());
                        headers.add("X-USER-ROLE", claims.get("role", String.class));
                        headers.add("X-COLLEGE-CODE", claims.get("collegeCode", String.class));
                    }))
                    .build();
        }
        catch (Exception e){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }
}
