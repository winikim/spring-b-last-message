package com.sparta.finalproject.auth.service.provider;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sparta.finalproject.auth.dto.AuthProviderUserInfoDto;
import com.sparta.finalproject.auth.entity.enums.AuthProvider;

public interface AuthProviderService {
    AuthProviderUserInfoDto getUserInfo(String code) throws JsonProcessingException;
    AuthProvider getAuthProvider();
}
