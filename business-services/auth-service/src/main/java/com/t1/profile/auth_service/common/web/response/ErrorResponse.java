package com.t1.profile.auth_service.common.web.response;

import java.time.LocalDateTime;

public record ErrorResponse(
        String message,
        String timestamp
) {

    public ErrorResponse(String message) {
        this(message, LocalDateTime.now().toString());
    }

}
