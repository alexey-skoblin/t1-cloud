package com.t1.profile.auth_service.service;

import com.t1.profile.auth_service.dto.ApiDto;
import com.t1.profile.auth_service.dto.JwtAuthenticationDto;
import com.t1.profile.auth_service.dto.LoginDto;
import com.t1.profile.auth_service.dto.RegistrationDto;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {

    ApiDto registerUser(RegistrationDto registrationDto);
    JwtAuthenticationDto authenticateUser(LoginDto loginDto);
    ApiDto logoutUser(HttpServletRequest request);

}
