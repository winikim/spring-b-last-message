package com.sparta.finalproject.auth.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class AuthProviderUserInfoDto {

    private Long id;
    private String email;
    private String nickname;

    public AuthProviderUserInfoDto(Long id, String nickname, String email) {
        this.id = id;
        this.nickname = nickname;
        this.email = email;
    }
}