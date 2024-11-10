package com.t1.profile.auth_service.security.jwt;

import com.t1.profile.auth_service.security.details.UserDetailsImpl;
import com.t1.profile.auth_service.security.exception.JwtTokenExpiredException;
import com.t1.profile.auth_service.security.exception.JwtTokenIllegalArgumentException;
import com.t1.profile.auth_service.security.exception.JwtTokenMalformedException;
import com.t1.profile.auth_service.security.exception.JwtTokenUnsupportedException;
import io.jsonwebtoken.*;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component
@Getter
public class JwtTokenProvider {

    private static final String TOKENS = "tokens:";

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    public String generateToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        String jti = UUID.randomUUID().toString();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        Set<String> userTokens = redisTemplate.opsForSet().members(TOKENS + userPrincipal.getUsername());

        if (userTokens != null) {
            for (String oldJti : userTokens) {
                redisTemplate.delete(oldJti);
            }
            redisTemplate.delete(TOKENS + userPrincipal.getUsername());
        }

        redisTemplate.opsForValue().set(jti, userPrincipal.getUsername(), jwtExpirationInMs, TimeUnit.MILLISECONDS);

        redisTemplate.opsForSet().add(TOKENS + userPrincipal.getUsername(), jti);

        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setId(jti)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJWT(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    public boolean validateToken(String authToken) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtSecret)
                    .parseClaimsJws(authToken)
                    .getBody();

            String jti = claims.getId();

            String username = redisTemplate.opsForValue().get(jti);
            if (username == null) {
                // Токен недействителен
                return false;
            }
            return true;
        } catch (MalformedJwtException ex) {
            throw new JwtTokenMalformedException(ex.getMessage());
        } catch (ExpiredJwtException ex) {
            throw new JwtTokenExpiredException(ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            throw new JwtTokenUnsupportedException(ex.getMessage());
        } catch (IllegalArgumentException ex) {
            throw new JwtTokenIllegalArgumentException(ex.getMessage());
        }
    }

}
