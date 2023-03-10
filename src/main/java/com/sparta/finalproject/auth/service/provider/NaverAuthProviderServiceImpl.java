package com.sparta.finalproject.auth.service.provider;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sparta.finalproject.auth.dto.AuthProviderUserInfoDto;
import com.sparta.finalproject.auth.entity.enums.AuthProvider;
import org.springframework.stereotype.Service;

@Service
public class NaverAuthProviderServiceImpl implements AuthProviderService{
    @Override
    public AuthProviderUserInfoDto getUserInfo(String code) throws JsonProcessingException {
        return null;
    }

    @Override
    public AuthProvider getAuthProvider() {
        return null;
    }
}
