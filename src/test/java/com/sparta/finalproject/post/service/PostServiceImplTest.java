package com.sparta.finalproject.post.service;

import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class PostServiceImplTest {

//    @Autowired
//    PostService postService;
//
//    @Autowired
//    UserRepository userRepository;
//
//    @DisplayName("1. 게시물 생성 & 단건 조회 테스트")
//    @Test
//    void createPostTest() {
//        // Given
//        String title = "title";
//        String content = "content";
//        User user = User.builder()
//            .userId("userId")
//            .password("password")
//            .email("email@email.com")
//            .role(UserRole.USER)
//            .build();
//
//        User savedUser = userRepository.save(user);
//
//        PostDto.CreatePost createPost = CreatePost.builder()
//            .title(title)
//            .content(content)
//            .build();
//
//        // When
//        Long postId = postService.createPost(createPost, savedUser);
//        PostDto.ResponsePost postById = postService.getPostById(postId);
//
//        // Then
//        assertThat(postById.getId()).isEqualTo(postId);
//        assertThat(postById.getTitle()).isEqualTo(title);
//        assertThat(postById.getContent()).isEqualTo(content);
//        assertThat(postById.getUserInfo().getId()).isEqualTo(savedUser.getId());
//        assertThat(postById.getUserInfo().getUserId()).isEqualTo(savedUser.getUserId());
//    }
//
//    @DisplayName("2. 게시물 수정 테스트")
//    @Test
//    @Transactional
//    void updatePostTest() {
//        // Given
//        User user = User.builder()
//            .userId("userId")
//            .password("password")
//            .email("email@email.com")
//            .role(UserRole.USER)
//            .build();
//
//        User savedUser = userRepository.save(user);
//
//        PostDto.CreatePost createPost = CreatePost.builder()
//            .title("title")
//            .content("content")
//            .build();
//
//        String updateTitle = "update title";
//        String updateContent = "update content";
//
//        PostDto.UpdatePost updatePost = UpdatePost.builder()
//            .title(updateTitle)
//            .content(updateContent)
//            .build();
//
//        Long postId = postService.createPost(createPost, savedUser);
//
//        // When
//        postService.updatePost(postId, updatePost, savedUser);
//
//        // Then
//        ResponsePost updatedPost = postService.getPostById(postId);
//
//        assertThat(updatedPost.getId()).isEqualTo(postId);
//        assertThat(updatedPost.getTitle()).isEqualTo(updateTitle);
//        assertThat(updatedPost.getContent()).isEqualTo(updateContent);
//    }
//
//    @DisplayName("3. 게시물 삭제 테스트")
//    @Test
//    @Transactional
//    void deletePostTest() {
//        // Given
//        User user = User.builder()
//            .userId("userId")
//            .password("password")
//            .email("email@email.com")
//            .role(UserRole.USER)
//            .build();
//
//        User savedUser = userRepository.save(user);
//
//        PostDto.CreatePost createPost = CreatePost.builder()
//            .title("title")
//            .content("content")
//            .build();
//
//        Long postId = postService.createPost(createPost, savedUser);
//
//        // When
//        postService.deletePost(postId, savedUser);
//
//        // Then
//        assertThatThrownBy(() -> postService.getPostById(postId)).isInstanceOf(
//                BadRequestException.class)
//            .hasMessageContaining("해당하는 게시물이 없습니다.");
//    }
//
//    @DisplayName("4. 게시물 검색 페이징 조회 테스트")
//    @Transactional
//    @Test
//    void getPostsBySearchCondition() {
//        // Given
//        User user = User.builder()
//            .userId("userId")
//            .password("password")
//            .email("email@email.com")
//            .role(UserRole.USER)
//            .build();
//
//        User savedUser = userRepository.save(user);
//
//        PostDto.CreatePost createPost = CreatePost.builder()
//            .title("title")
//            .content("content")
//            .build();
//
//        postService.createPost(createPost, savedUser);
//
//        PostDto.SearchPost searchPost = PostDto.SearchPost.builder()
//            .title("ti")
//            .content("con")
//            .build();
//
//        // When
//        Page<ResponsePostList> findPosts = postService.getPosts(PageRequest.of(0, 10), searchPost);
//
//        // Then
//        assertThat(findPosts.getTotalElements()).isEqualTo(1);
//    }
//
//    @DisplayName("5. 관리자 - 게시물 삭제 테스트")
//    @Transactional
//    @Test
//    void deletePostAdminTest() {
//        // Given
//        User user = User.builder()
//            .userId("userId")
//            .password("password")
//            .email("email@email.com")
//            .role(UserRole.USER)
//            .build();
//
//        User savedUser = userRepository.save(user);
//
//        PostDto.CreatePost createPost = CreatePost.builder()
//            .title("title")
//            .content("content")
//            .build();
//
//        Long postId = postService.createPost(createPost, savedUser);
//        SearchPost searchPost = SearchPost.builder()
//            .title("ti")
//            .content("con")
//            .build();
//
//        // When
//        postService.deletePostAdmin(postId);
//
//        // Then
//        Page<ResponsePostList> posts = postService.getPosts(PageRequest.of(0, 10), searchPost);
//
//        assertThat(posts.getTotalElements()).isEqualTo(0);
//    }
}