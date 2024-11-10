package com.t1.profile.auth_service.exception;

public class UserNotFoundException extends RuntimeException {

    private static final String MESSAGE_TEMPLATE = "User not found with email: ";

    public UserNotFoundException(String email) {
        super(MESSAGE_TEMPLATE + email);
    }

    public static String getMessage(String email) {
        return MESSAGE_TEMPLATE + email;
    }


}