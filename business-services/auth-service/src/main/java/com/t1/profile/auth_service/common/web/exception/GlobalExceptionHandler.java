package com.t1.profile.auth_service.common.web.exception;

import com.t1.profile.auth_service.common.web.response.ErrorResponse;
import com.t1.profile.auth_service.exception.*;
import com.t1.profile.auth_service.security.exception.JwtTokenExpiredException;
import com.t1.profile.auth_service.security.exception.JwtTokenIllegalArgumentException;
import com.t1.profile.auth_service.security.exception.JwtTokenMalformedException;
import com.t1.profile.auth_service.security.exception.JwtTokenUnsupportedException;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

import javax.naming.AuthenticationException;

@ControllerAdvice
@Log4j2
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    @ExceptionHandler(UserNotFoundException.class)
    @SneakyThrows
    ResponseEntity<Object> handleUserNotFoundException(
            UserNotFoundException ex,
            WebRequest request
    ) {
        log.error("UserNotFoundException occurred: ", ex);
        log.info("request: {}", request);

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(AuthenticationException.class)
    @SneakyThrows
    public ResponseEntity<Object> handleAuthenticationException(
            AuthenticationException ex,
            WebRequest request
    ) {
        String requestURI = request.getDescription(false);

        log.error("Unauthorized request to URI: {}. Exception: ", requestURI, ex);
        log.info("Request: {}", request);

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(JwtTokenExpiredException.class)
    public ResponseEntity<Object> handleJwtTokenExpiredException(
            JwtTokenExpiredException ex,
            WebRequest request
    ) {
        log.error("JwtTokenExpiredException occurred: ", ex);
        log.info("request: {}", request);

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(JwtTokenMalformedException.class)
    public ResponseEntity<Object> handleJwtTokenMalformedException(
            JwtTokenMalformedException ex,
            WebRequest request
    ) {
        log.error("JwtTokenMalformedException occurred: ", ex);
        log.info("request: {}", request);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(JwtTokenUnsupportedException.class)
    public ResponseEntity<Object> handleJwtTokenUnsupportedException(
            JwtTokenUnsupportedException ex,
            WebRequest request
    ) {
        log.error("JwtTokenUnsupportedException occurred: ", ex);
        log.info("request: {}", request);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(JwtTokenIllegalArgumentException.class)
    public ResponseEntity<Object> handleJwtTokenIllegalArgumentException(
            JwtTokenIllegalArgumentException ex,
            WebRequest request
    ) {
        log.error("JwtTokenIllegalArgumentException occurred: ", ex);
        log.info("request: {}", request);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(ex.getMessage()));
    }

}
