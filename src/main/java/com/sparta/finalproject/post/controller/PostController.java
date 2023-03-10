package com.sparta.finalproject.post.controller;

import com.sparta.finalproject.common.core.PageWrapper;
import com.sparta.finalproject.common.security.UserDetailsImpl;
import com.sparta.finalproject.post.dto.CreatePost;
import com.sparta.finalproject.post.dto.PostsDto;
import com.sparta.finalproject.post.dto.ResponsePost;
import com.sparta.finalproject.post.dto.SearchPost;
import com.sparta.finalproject.post.dto.UpdatePost;
import com.sparta.finalproject.post.service.PostService;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * HttpServeltReqeust는 Controller를 넘어갈 수 없다.
 * 만약에, WebFlux Servelt을 안쓰게 되. 그러면 kakaoLogin 함수는 버려야되.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/posts")
public class PostController {

    private final PostService postService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
    public Long createPost(@RequestBody @Valid CreatePost createPost,
        @AuthenticationPrincipal UserDetailsImpl userDetails) {
        return postService.createPost(createPost, userDetails.getUser());
    }

    @GetMapping("/{postId}")
    @ResponseStatus(HttpStatus.OK)
    public ResponsePost getPostById(@PathVariable Long postId) {

        return postService.getPostById(postId);
    }

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public PageWrapper getPosts(SearchPost searchPost,
        @PageableDefault() Pageable pageable) {
        return PageWrapper.of(postService.getPosts(pageable, searchPost));
    }

    @PutMapping("/{postId}")
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
    public Long updatePost(@PathVariable Long postId,
        @RequestBody @Valid UpdatePost updatePost,
        @AuthenticationPrincipal UserDetailsImpl userDetails) {

        return postService.updatePost(postId, updatePost, userDetails.getUser());
    }

    @DeleteMapping("/{postId}")
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
    public void deletePost(@PathVariable Long postId,
        @AuthenticationPrincipal UserDetailsImpl userDetails) {

        postService.deletePost(postId, userDetails.getUser());
    }

    @GetMapping("/my-page")
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
    public PageWrapper<PostsDto> selectMyPostLists(@PageableDefault() Pageable pageable,
        @AuthenticationPrincipal UserDetailsImpl userDetails) {
        return PageWrapper.of(
            postService.selectMyPostLists(pageable, userDetails.getUser().getId()));
    }
}
