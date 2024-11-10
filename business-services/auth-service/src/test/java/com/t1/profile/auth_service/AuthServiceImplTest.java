package com.t1.profile.auth_service;

import com.t1.profile.auth_service.dto.ApiDto;
import com.t1.profile.auth_service.dto.JwtAuthenticationDto;
import com.t1.profile.auth_service.dto.LoginDto;
import com.t1.profile.auth_service.dto.RegistrationDto;
import com.t1.profile.auth_service.model.User;
import com.t1.profile.auth_service.repository.UserRepo;
import com.t1.profile.auth_service.security.jwt.JwtTokenProvider;
import com.t1.profile.auth_service.service.AuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class AuthServiceImplTest {

    @InjectMocks
    private AuthServiceImpl authService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserRepo userRepo;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenProvider tokenProvider;

    @Mock
    private Authentication authentication;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testRegisterUser_Success() {
        RegistrationDto registrationDto = new RegistrationDto();
        registrationDto.setFirstName("John");
        registrationDto.setLastName("Doe");
        registrationDto.setEmail("john.doe@example.com");
        registrationDto.setPassword("password123");

        when(userRepo.findByEmail(registrationDto.getEmail())).thenReturn(null);

        when(userRepo.save(any(User.class))).thenReturn(new User());

        ApiDto response = authService.registerUser(registrationDto);

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).isEqualTo(MessageType.USER_REGISTERED_SUCCESSFULLY);
        verify(userRepo, times(1)).findByEmail(registrationDto.getEmail());
        verify(userRepo, times(1)).save(any(User.class));
    }

    @Test
    public void testRegisterUser_EmailAlreadyInUse() {
        RegistrationDto registrationDto = new RegistrationDto();
        registrationDto.setEmail("john.doe@example.com");

        when(userRepo.findByEmail(registrationDto.getEmail())).thenReturn(new User());

        ApiDto response = authService.registerUser(registrationDto);

        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).isEqualTo(MessageType.EMAIL_ALREADY_USE);
        verify(userRepo, times(1)).findByEmail(registrationDto.getEmail());
        verify(userRepo, never()).save(any(User.class));
    }

    @Test
    public void testAuthenticateUser_Success() {
        LoginDto loginDto = new LoginDto();
        loginDto.setEmail("john.doe@example.com");
        loginDto.setPassword("password123");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(tokenProvider.generateToken(authentication)).thenReturn("jwt-token");

        JwtAuthenticationDto response = authService.authenticateUser(loginDto);

        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo("jwt-token");
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(tokenProvider, times(1)).generateToken(authentication);
    }

    @Test
    public void testAuthenticateUser_Failure() {
        LoginDto loginDto = new LoginDto();
        loginDto.setEmail("john.doe@example.com");
        loginDto.setPassword("wrongpassword");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new RuntimeException("Authentication failed"));

        try {
            authService.authenticateUser(loginDto);
            fail("Expected RuntimeException to be thrown");
        } catch (RuntimeException e) {
            assertThat(e.getMessage()).isEqualTo("Authentication failed");
        }

        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }
}
