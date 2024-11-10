package com.t1.profile.auth_service.dto;

import lombok.Data;

@Data
public class ApiDto {

    private Boolean success;
    private String message;

    public ApiDto(Boolean success, String message) {
        this.success = success;
        this.message = message;
    }

    public Boolean isSuccess() {
        return success;
    }

}
