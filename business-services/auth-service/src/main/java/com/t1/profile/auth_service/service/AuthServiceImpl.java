package com.t1.profile.auth_service.service;

import com.t1.profile.auth_service.dto.ApiDto;
import com.t1.profile.auth_service.dto.JwtAuthenticationDto;
import com.t1.profile.auth_service.dto.LoginDto;
import com.t1.profile.auth_service.dto.RegistrationDto;
import com.t1.profile.auth_service.model.Role;
import com.t1.profile.auth_service.model.User;
import com.t1.profile.auth_service.repository.UserRepo;
import com.t1.profile.auth_service.security.jwt.JwtFromRequest;
import com.t1.profile.auth_service.security.jwt.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collections;

import static com.t1.profile.auth_service.MessageType.*;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Override
    public ApiDto registerUser(RegistrationDto registrationDto) {
        if (userRepo.findByEmail(registrationDto.getEmail()) != null) {
            return new ApiDto(false, EMAIL_ALREADY_USE);
        }

        User user = new User();
        user.setEmail(registrationDto.getEmail());
        user.setFirstName(registrationDto.getFirstName());
        user.setLastName(registrationDto.getLastName());
        user.setPasswordHash(passwordEncoder.encode(registrationDto.getPassword()));

        user.setRoles(Collections.singleton(Role.ROLE_USER));

        userRepo.save(user);

        return new ApiDto(true, USER_REGISTERED_SUCCESSFULLY);
    }

    @Override
    public JwtAuthenticationDto authenticateUser(LoginDto loginDto) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginDto.getEmail(),
                            loginDto.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = tokenProvider.generateToken(authentication);

            User user = userRepo.findByEmail(loginDto.getEmail());

            if (user.getRoles().contains(Role.ROLE_ADMIN)) {
                return new JwtAuthenticationDto(jwt, Role.ROLE_ADMIN.name());
            }

            return new JwtAuthenticationDto(jwt, Role.ROLE_USER.name());

        } catch (BadCredentialsException e) {
            throw new BadCredentialsException(WRONG_EMAIL_OR_PASSWORD);
        }
    }

    @Override
    public ApiDto logoutUser(HttpServletRequest request) {
        String token = JwtFromRequest.getJwt(request);
        if (token != null && tokenProvider.validateToken(token)) {
            Claims claims = Jwts.parser()
                    .setSigningKey(tokenProvider.getJwtSecret())
                    .parseClaimsJws(token)
                    .getBody();
            String jti = claims.getId();
            redisTemplate.delete(jti);
            return new ApiDto(true, LOGGED_OUT);
        }
        return new ApiDto(false, UNABLE_LOGGED_OUT);
    }

}
