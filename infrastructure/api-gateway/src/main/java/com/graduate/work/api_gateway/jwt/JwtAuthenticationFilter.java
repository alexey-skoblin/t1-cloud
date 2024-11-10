package com.graduate.work.api_gateway.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.util.Collections;

@Component
public class JwtAuthenticationFilter implements
        org.springframework.web.server.WebFilter {
    @Autowired
    private JwtTokenProvider tokenProvider;

    @Override
    public Mono<Void> filter(
            ServerWebExchange exchange,
            org.springframework.web.server.WebFilterChain chain
    ) {
        String path = exchange.getRequest().getURI().getPath();
        if (path.startsWith("/auth/")) {
            return chain.filter(exchange);
        }
        String token = getJwtFromRequest(exchange.getRequest());
        if (token != null && tokenProvider.validateToken(token)) {
            String username = tokenProvider.getUsernameFromJWT(token);
            Authentication auth = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    Collections.emptyList());
            return chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
        }
        return chain.filter(exchange);
    }

    private String getJwtFromRequest(ServerHttpRequest request) {
        String bearerToken =
                request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}