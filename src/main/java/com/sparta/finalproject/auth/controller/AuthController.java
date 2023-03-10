package com.sparta.finalproject.auth.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sparta.finalproject.auth.dto.DeleteRequestDto;
import com.sparta.finalproject.auth.dto.LoginDto;
import com.sparta.finalproject.auth.dto.SignupDto;
import com.sparta.finalproject.auth.dto.TokenDto;
import com.sparta.finalproject.auth.entity.enums.AuthProvider;
import com.sparta.finalproject.auth.service.AuthService;
import com.sparta.finalproject.common.security.UserDetailsImpl;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    //회원가입
    @PostMapping("/signup")
    public void signup(@RequestBody @Valid SignupDto signupDto) {
        authService.signup(signupDto);
    }

    //로그인
    @PostMapping("/login")
    public void login(@RequestBody LoginDto loginDto, HttpServletResponse response) {
        authService.login(loginDto, response);
    }


    //로그아웃
    @DeleteMapping("/logout")
    @ResponseStatus(HttpStatus.OK)
    public void signOut(final @RequestBody TokenDto tokenDto) {
        authService.logout(tokenDto);
    }

    //회원 탈퇴
    @DeleteMapping("/delete")
    public void delete(@RequestBody DeleteRequestDto deleteRequestDto,
        UserDetailsImpl userDetails) {
        authService.delete(deleteRequestDto, userDetails.getUser());
    }

    //토큰 재발행
    @PostMapping("/reissue")
    public void reIssue(@RequestBody TokenDto tokenDto, HttpServletResponse response) {
        authService.reIssue(tokenDto, response);
    }


    /**
     * OAUHT2
     * 4가지 gran_type
     * 1. Authorization_code 방식..
     * 2. 구글 로그인
     * @param code
     * @return
     * @throws JsonProcessingException
     *
     * code 받으면, JWT TOKEN을 주면 됨.
     */

    //카카오 로그인 , http://localhost:8080/api/auth/GOOGLE/social-lgin
    @GetMapping("/{authProvider}/social-login")  // http://localhost:8080/api/auth/KAKAO/social-lgin
    public String socialLogin(@PathVariable AuthProvider authProvider, @RequestParam String code)
        throws JsonProcessingException {
        // code: 카카오 서버로부터 받은 인가 코드
        // 소셜 로그인 = 프로바이더(구글 카카오)의 code를 받으면 우리가 generate한  JWT TOKEN을 준다.
        String createToken = authService.socialLogin(authProvider, code);

        return createToken;
    }

    //이메일 인증
    @PostMapping("/emailConfirm")
    public void emailConfirm(@RequestParam String email) throws Exception {

        authService.sendSimpleMessage(email);

    }

}
