package com.t1.profile.auth_service.security.jwt;

import jakarta.servlet.http.HttpServletRequest;

public class JwtFromRequest {

    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER = "Bearer ";

    public static String getJwt(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith(BEARER)) {
            return bearerToken.substring(7);
        }
        return null;
    }

}
