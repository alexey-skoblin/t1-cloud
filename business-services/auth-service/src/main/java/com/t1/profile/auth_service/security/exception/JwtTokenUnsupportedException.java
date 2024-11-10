package com.t1.profile.auth_service.security.exception;

public class JwtTokenUnsupportedException extends RuntimeException {

    private static final String MESSAGE_TEMPLATE = "JWT token is unsupported: ";

    public JwtTokenUnsupportedException(String message) {
        super(MESSAGE_TEMPLATE + message);
    }

    public static String getMessage(String message) {
        return MESSAGE_TEMPLATE + message;
    }

}
