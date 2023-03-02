package com.sparta.finalproject.post.dto;

import com.sparta.finalproject.post.entity.Post;
import com.sparta.finalproject.user.dto.UserDto.ResponseUserWithPost;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;
import javax.validation.constraints.NotBlank;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.format.annotation.DateTimeFormat.ISO;

public class PostDto {

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class CreatePost {

        @NotBlank
        private String title;

        @NotBlank
        private String content;

        @Builder
        public CreatePost(String title, String content) {
            this.title = title;
            this.content = content;
        }
    }

    @Getter
    public static class ResponsePost {

        private Long id;
        private String title;
        private String content;
        private ResponseUserWithPost userInfo;
        private LocalDateTime createdAt;
        private LocalDateTime modifiedAt;

        private ResponsePost(Post post) {
            this.id = post.getId();
            this.title = post.getTitle();
            this.content = post.getContent();
            this.userInfo = ResponseUserWithPost.of(post.getUser());
            this.createdAt = post.getCreatedAt();
            this.modifiedAt = post.getModifiedAt();
        }

        public static ResponsePost of(Post post) {
            return new ResponsePost(post);
        }

        public static List<ResponsePost> of(List<Post> posts) {
            return posts.stream().map(ResponsePost::of).collect(Collectors.toList());
        }
    }

    @Getter
    public static class ResponsePostList {

        private Long id;
        private String title;
        private String content;
        private ResponseUserWithPost userInfo;
        private LocalDateTime createdAt;
        private LocalDateTime modifiedAt;
        private long likeCnt;

        private ResponsePostList(Post post, long likeCnt) {
            this.id = post.getId();
            this.title = post.getTitle();
            this.content = post.getContent();
            this.userInfo = ResponseUserWithPost.of(post.getUser());
            this.createdAt = post.getCreatedAt();
            this.modifiedAt = post.getModifiedAt();
            this.likeCnt = likeCnt;
        }

        public static ResponsePostList of(Post post, long likeCnt) {
            return new ResponsePostList(post, likeCnt);
        }
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class UpdatePost {

        @NotBlank
        private String title;

        @NotBlank
        private String content;

        @Builder
        public UpdatePost(String title, String content) {
            this.title = title;
            this.content = content;
        }
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class SearchPost {

        private String title;
        private String content;

        @Builder
        public SearchPost(String title, String content) {
            this.title = title;
            this.content = content;
        }
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class SearchPostAdmin {

        private String title;
        private String content;
        private String userId;

        @DateTimeFormat(iso = ISO.DATE_TIME)
        private LocalDateTime createdStarted;

        @DateTimeFormat(iso = ISO.DATE_TIME)
        private LocalDateTime createdEnded;

        @Builder
        public SearchPostAdmin(String title, String content, String userId,
            LocalDateTime createdStarted, LocalDateTime createdEnded) {
            this.title = title;
            this.content = content;
            this.userId = userId;
            this.createdStarted = createdStarted;
            this.createdEnded = createdEnded;
        }
    }
}