package com.t1.profile.auth_service.security.exception;

public class JwtTokenIllegalArgumentException extends RuntimeException {

    private static final String MESSAGE_TEMPLATE = "JWT token is empty or invalid: ";

    public JwtTokenIllegalArgumentException(String message) {
        super(MESSAGE_TEMPLATE + message);
    }

    public static String getMessage(String message) {
        return MESSAGE_TEMPLATE + message;
    }
}
