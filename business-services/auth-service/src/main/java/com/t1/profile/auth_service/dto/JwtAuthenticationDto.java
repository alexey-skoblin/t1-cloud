package com.t1.profile.auth_service.dto;

import lombok.Data;

@Data
public class JwtAuthenticationDto {

    private String accessToken;
    private String tokenType = "Bearer";
    private String roleType;

    public JwtAuthenticationDto(String accessToken, String roleType) {
        this.accessToken = accessToken;
        this.roleType = roleType;
    }

    public JwtAuthenticationDto(String accessToken) {
        this.accessToken = accessToken;
    }

}
