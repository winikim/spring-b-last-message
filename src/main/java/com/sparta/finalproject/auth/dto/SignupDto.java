package com.sparta.finalproject.auth.dto;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import lombok.Getter;

@Getter
public class SignupDto {

    @NotBlank
    @Size(min = 4, max = 8)
    @Pattern(regexp = "^[a-z0-9]*$", message = "최소 4자 이상, 10자 이하이며 a-z, 0-9 만 입력하세요.")
    private String userId;

    @NotBlank
    @Size(min = 8, max = 15)
    @Pattern(regexp = "^[a-zA-Z0-9]*$", message = "최소 8자 이상, 15자 이하이며 a-z, A-Z, 0-9 만 입력하세요.")
    private String password;

    @Email
    @NotBlank
    private String email;

    private boolean admin = false;
    private String adminKey = "";
}