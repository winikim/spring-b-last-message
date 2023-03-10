package com.sparta.finalproject.auth.service.provider;

import com.sparta.finalproject.auth.entity.enums.AuthProvider;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;

@Component
public class AuthProviderFactory {
    private final List<AuthProviderService> authProviderServiceList; // KakaoAuthProviderSErviceImpl, NaverAuthProvidrSErvCE

    private HashMap<AuthProvider, AuthProviderService> map = new HashMap<>();

    public AuthProviderFactory(List<AuthProviderService> authProviderServiceList) {
        this.authProviderServiceList = authProviderServiceList;
        for(AuthProviderService authProviderService : this.authProviderServiceList) {
            this.map.put(authProviderService.getAuthProvider(), authProviderService);
        }
    }

    public AuthProviderService getService(AuthProvider authProvider) {
        return this.map.get(authProvider);
    }
}
