package com.t1.profile.auth_service.security.jwt;

import com.t1.profile.auth_service.security.details.UserDetailsServiceImpl;
import com.t1.profile.auth_service.security.exception.JwtTokenExpiredException;
import com.t1.profile.auth_service.security.exception.JwtTokenIllegalArgumentException;
import com.t1.profile.auth_service.security.exception.JwtTokenMalformedException;
import com.t1.profile.auth_service.security.exception.JwtTokenUnsupportedException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String OPTIONS = "OPTIONS";

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (OPTIONS.equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            filterChain.doFilter(request, response);
            return;
        }
        try {
            String jwt = JwtFromRequest.getJwt(request);

            if (jwt != null && tokenProvider.validateToken(jwt)) {
                String email = tokenProvider.getUserNameFromJWT(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(email);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (ExpiredJwtException ex) {
            throw new JwtTokenExpiredException(ex.getMessage());
        } catch (MalformedJwtException ex) {
            throw new JwtTokenMalformedException(ex.getMessage());
        }  catch (UnsupportedJwtException ex) {
            throw new JwtTokenUnsupportedException(ex.getMessage());
        } catch (IllegalArgumentException ex) {
            throw new JwtTokenIllegalArgumentException(ex.getMessage());
        }

        filterChain.doFilter(request, response);
    }

}
