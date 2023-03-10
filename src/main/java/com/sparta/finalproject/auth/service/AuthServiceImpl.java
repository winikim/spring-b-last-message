package com.sparta.finalproject.auth.service;

import static com.sparta.finalproject.common.jwt.JwtUtil.AUTHORIZATION_HEADER;
import static com.sparta.finalproject.common.jwt.JwtUtil.REFRESH_TOKEN_VALID_TIME;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparta.finalproject.auth.dto.DeleteRequestDto;
import com.sparta.finalproject.auth.dto.AuthProviderUserInfoDto;
import com.sparta.finalproject.auth.dto.LoginDto;
import com.sparta.finalproject.auth.dto.SignupDto;
import com.sparta.finalproject.auth.dto.TokenDto;
import com.sparta.finalproject.auth.entity.enums.AuthProvider;
import com.sparta.finalproject.auth.service.provider.AuthProviderFactory;
import com.sparta.finalproject.auth.service.provider.AuthProviderService;
import com.sparta.finalproject.common.exception.BadRequestException;
import com.sparta.finalproject.common.jwt.JwtUtil;
import com.sparta.finalproject.common.redis.RedisUtil;
import com.sparta.finalproject.user.entity.User;
import com.sparta.finalproject.user.entity.UserRole;
import com.sparta.finalproject.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import javax.mail.Message.RecipientType;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    @Autowired
    JavaMailSender emailSender;
    public static final String ePw = createKey();
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RedisUtil redisUtil;
    private static final String ADMIN_KEY = "AAABnvxRVklrnYxKZ0aHgTBcXukeZygoC";
    private final AuthProviderFactory authProviderFactory;

    @Override
    @Transactional
    public void signup(SignupDto signupDto) {
        String userId = signupDto.getUserId();
        String password = passwordEncoder.encode(signupDto.getPassword());

        //회원중복확인
        Optional<User> found = userRepository.findByUserId(userId);

        if (found.isPresent()) {
            throw new IllegalArgumentException("중복된 username 입니다.");
        }

        String email = signupDto.getEmail();

        //사용자 Role 확인
        UserRole role = UserRole.USER;
        if (signupDto.isAdmin()) {
            if (!signupDto.getAdminKey().equals(ADMIN_KEY)) {
                throw new IllegalArgumentException("관리자 키가 틀려 등록이 불가능 합니다.");
            }
            role = UserRole.ADMIN;
        }

        User user = User.builder().userId(userId).password(password).email(email).role(role)
            .build();

        userRepository.save(user);
    }

    @Override
    @Transactional
    public void login(LoginDto loginDto, HttpServletResponse response) {
        String userId = loginDto.getUserId();
        String password = loginDto.getPassword();

        User user = userRepository.findByUserId(userId).orElseThrow(
            () -> new IllegalArgumentException("등록된 사용자가 없습니다.")
        );

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        String refreshToken = jwtUtil.createRefreshToken();
        user.updateRefreshToken(refreshToken);

        userRepository.saveAndFlush(user);
        redisUtil.setDataExpire(user.getUserId(), refreshToken, REFRESH_TOKEN_VALID_TIME);
        addTokenToHeader(response, user, refreshToken);
    }

    @Override
    @Transactional
    public void logout(TokenDto tokenDto) {

        String accessToken = tokenDto.getAccessToken().substring(7);
        if (!jwtUtil.validateToken(accessToken)) {
            throw new IllegalArgumentException("유효하지 않은 access token");
        }

        Claims claim = jwtUtil.getUserInfoFromToken(accessToken);
        String userId = claim.getSubject();
        redisUtil.deleteData(userId);

        redisUtil.setDataExpire("JWT:BLACK_LIST:" + accessToken, "TRUE", 30);
    }


    @Override
    @Transactional
    public void delete(DeleteRequestDto deleteRequestDto, User user) {
        user = userRepository.findByUserId(deleteRequestDto.getUserId()).orElseThrow(
            () -> new BadRequestException("해당하는 사용자가 없습니다")
        );

        userRepository.delete(user);
    }

    @Transactional
    public void reIssue(TokenDto tokenDto, HttpServletResponse response) {
        if (!jwtUtil.validateTokenExceptExpiration(tokenDto.getRefreshToken())) {
            throw new IllegalArgumentException("유효하지 않은 토큰입니다.");
        }

        User user = findUserByToken(tokenDto);

        if (!user.getRefreshToken().equals(tokenDto.getRefreshToken())) {
            throw new IllegalArgumentException("유효하지 않은 토큰입니다.");
        }

        String refreshToken = jwtUtil.createRefreshToken();

        user.updateRefreshToken(refreshToken);
        userRepository.saveAndFlush(user);

        addTokenToHeader(response, user, refreshToken);
    }

    @Transactional
    public void addTokenToHeader(HttpServletResponse response, User user, String refreshToken) {
        response.addHeader(AUTHORIZATION_HEADER,
            jwtUtil.createToken(user.getUserId(), user.getRole()));
        response.addHeader(JwtUtil.REFRESH_HEADER, refreshToken);
    }

    private User findUserByToken(TokenDto tokenDto) {
        Claims claims = jwtUtil.getUserInfoFromToken(tokenDto.getAccessToken().substring(7));
        String userId = claims.getSubject();
        return userRepository.findByUserId(userId).orElseThrow(
            () -> new IllegalArgumentException("존재하지 않는 사용자입니다.")
        );
    }

    private MimeMessage createMessage(String to) throws Exception {

        MimeMessage message = emailSender.createMimeMessage();

        message.addRecipients(RecipientType.TO, to);//보내는 대상
        message.setSubject("[GRASP] 인증번호를 안내해드립니다.");//제목

        String msgg = "";
        msgg += "<div style='margin:20px;'>";
        msgg += "<h1> 안녕하세요 GRASP입니다. </h1>";
        msgg += "<br>";
        msgg += "<p>아래의 인증번호를 GRASP에 입력해주세요.<p>";
        msgg += "<br>";
        msgg += "<p>인증번호는 5분 후 만료되니, 반드시 5분 내에 입력 하시기 바랍니다.<p>";
        msgg += "<br>";
        msgg += "<p>감사합니다.<p>";
        msgg += "<br>";
        msgg += "<div align='center' style='border:1px solid black; font-family:Sans-Serif';>";
        msgg += "<h3 style='color:blue;'>회원가입 인증 코드입니다.</h3>";
        msgg += "<div style='font-size:130%'>";
        msgg += "CODE : <strong>";
        msgg += ePw + "</strong><div><br/> ";
        msgg += "</div>";
        message.setText(msgg, "utf-8", "html");//내용
        message.setFrom(new InternetAddress("sulsa1544@gmail.com", "GRASP"));//보내는 사람

        return message;
    }

    public static String createKey() {
        StringBuffer key = new StringBuffer();
        Random rnd = new Random();

        for (int i = 0; i < 8; i++) { // 인증코드 8자리
            int index = rnd.nextInt(3); // 0~2 까지 랜덤

            switch (index) {
                case 0:
                    key.append((char) ((int) (rnd.nextInt(26)) + 97));
                    //  a~z  (ex. 1+97=98 => (char)98 = 'b')
                    break;
                case 1:
                    key.append((char) ((int) (rnd.nextInt(26)) + 65));
                    //  A~Z
                    break;
                case 2:
                    key.append((rnd.nextInt(10)));
                    // 0~9
                    break;
            }
        }
        return key.toString();
    }

    @Override
    public void sendSimpleMessage(String to) throws Exception {
        MimeMessage message = createMessage(to);

        try {//예외처리
            emailSender.send(message);
        } catch (MailException es) {
            es.printStackTrace();
            throw new IllegalArgumentException();
        }
        // 유효 시간(5분)동안 저장
        redisUtil.setDataExpire("email: " + to, "code: " + ePw, 60 * 5L);

    }

    @Override
    public String socialLogin(AuthProvider authProvider, String code)
        throws JsonProcessingException {

        AuthProviderUserInfoDto authProviderUserInfoDto = authProviderFactory.getService(authProvider).getUserInfo(code);

//        AuthProviderUserInfoDto authProviderUserInfoDto = authProviderService.getUserInfo(code);
//        // 1. "인가 코드"로 "액세스 토큰" 요청
//        String accessToken = getToken(code);
//
//        // 2. 토큰으로 카카오 API 호출 : "액세스 토큰"으로 "카카오 사용자 정보" 가져오기
//        AuthProviderUserInfoDto kakaoUserInfo = getKakaoUserInfo(accessToken);

        // 3. 필요시에 회원가입
        User kakaoUser = registerKakaoUserIfNeeded(authProviderUserInfoDto);

        // 4. JWT 토큰 반환
        String createToken = jwtUtil.createToken(kakaoUser.getUserId(), kakaoUser.getRole());

        return createToken;
    }


    // 3. 필요시에 회원가입
    private User registerKakaoUserIfNeeded(AuthProviderUserInfoDto kakaoUserInfo) {
        // DB 에 중복된 Kakao Id 가 있는지 확인
        Long kakaoId = kakaoUserInfo.getId();
        User kakaoUser = userRepository.findByKakaoId(kakaoId)
            .orElse(null);
        if (kakaoUser == null) {
            // 카카오 사용자 email 동일한 email 가진 회원이 있는지 확인
            String kakaoEmail = kakaoUserInfo.getEmail();
            User sameEmailUser = userRepository.findByEmail(kakaoEmail).orElse(null);
            if (sameEmailUser != null) {
                kakaoUser = sameEmailUser;
                // 기존 회원정보에 카카오 Id 추가
                kakaoUser = kakaoUser.kakaoIdUpdate(kakaoId);
            } else {
                // 신규 회원가입
                // password: random UUID
                String password = UUID.randomUUID().toString();
                String encodedPassword = passwordEncoder.encode(password);

                // email: kakao email
                String email = kakaoUserInfo.getEmail();

                List<String> frontRandom = new ArrayList<>(Arrays.asList
                    ("똑똑한", "현명한", "바보", "배고픈", "총명한", "아픈"));
                List<String> backRandom = new ArrayList<>(Arrays.asList("익현", "태이", "준혁", "동현"));

                Random rd = new Random();

                String nickName = frontRandom.get(rd.nextInt(6)) + " "
                    + backRandom.get((rd.nextInt(4)));

                while (userRepository.existsByUserId(nickName)) {
                    nickName += "1";
                }

                kakaoUser = new User(nickName, kakaoId, encodedPassword, email,
                    UserRole.USER);
            }

            userRepository.save(kakaoUser);
        }
        return kakaoUser;
    }
}
