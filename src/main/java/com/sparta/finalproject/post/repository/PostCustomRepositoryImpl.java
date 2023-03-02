package com.sparta.finalproject.post.repository;

import static com.sparta.finalproject.like.entity.QLike.like;
import static com.sparta.finalproject.post.entity.QPost.post;

import com.querydsl.core.Tuple;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.core.types.dsl.Wildcard;
import com.querydsl.jpa.JPAExpressions;
import com.querydsl.jpa.impl.JPAQueryFactory;
import com.sparta.finalproject.post.dto.PostDto;
import com.sparta.finalproject.post.dto.PostDto.ResponsePost;
import com.sparta.finalproject.post.dto.PostDto.SearchPostAdmin;
import com.sparta.finalproject.post.entity.Post;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;
import org.springframework.stereotype.Repository;

@Repository
public class PostCustomRepositoryImpl extends QuerydslRepositorySupport implements
    PostCustomRepository {

    private final JPAQueryFactory jpaQueryFactory;

    public PostCustomRepositoryImpl(JPAQueryFactory jpaQueryFactory) {
        super(Post.class);
        this.jpaQueryFactory = jpaQueryFactory;
    }

    private BooleanExpression searchByTitle(String title) {
        return Objects.nonNull(title) ? post.title.contains(title) : null;
    }

    private BooleanExpression searchByContent(String content) {
        return Objects.nonNull(content) ? post.content.contains(content) : null;
    }

    private BooleanExpression searchByUserId(String userId) {
        return Objects.nonNull(userId) ? post.user.userId.contains(userId) : null;
    }

    private BooleanExpression searchByCreated(LocalDateTime createdStarted,
        LocalDateTime createdEnded) {
        if (Objects.nonNull(createdStarted) && Objects.nonNull(createdEnded)) {
            return post.createdAt.between(createdStarted, createdEnded);
        }
        return null;
    }

    @Override
    public Page<PostDto.ResponsePostList> getPostsBySearchCondition(Pageable pageable,
        PostDto.SearchPost searchPost) {
        List<Tuple> posts = jpaQueryFactory.select(post,
                JPAExpressions.select(Wildcard.count).from(like)
                    .where(post.id.eq(like.post.id))
            )
            .from(post)
            .where(
                searchByTitle(searchPost.getTitle()),
                searchByContent(searchPost.getContent())
            )
            .offset(pageable.getOffset())
            .limit(pageable.getPageSize())
            .fetch();

        Long postCount = jpaQueryFactory.select(Wildcard.count)
            .from(post)
            .where(
                searchByTitle(searchPost.getTitle()),
                searchByContent(searchPost.getContent())
            ).fetch().get(0);

        List<PostDto.ResponsePostList> responsePostList = new ArrayList<>();
        for (Tuple tuple : posts) {
            responsePostList.add(
                PostDto.ResponsePostList.of(Objects.requireNonNull(tuple.get(0, Post.class)),
                    Objects.nonNull(tuple.get(1, Long.class)) ? tuple.get(1, Long.class) : 0));
        }

        return new PageImpl<>(responsePostList, pageable, postCount);
    }

    @Override
    public Page<ResponsePost> selectPostsBySearchConditionAdmin(SearchPostAdmin searchPostAdmin,
        Pageable pageable) {

        List<Post> posts = jpaQueryFactory.selectFrom(post)
            .where(
                searchByTitle(searchPostAdmin.getTitle()),
                searchByContent(searchPostAdmin.getContent()),
                searchByUserId(searchPostAdmin.getUserId()),
                searchByCreated(searchPostAdmin.getCreatedStarted(),
                    searchPostAdmin.getCreatedEnded())
            )
            .offset(pageable.getOffset())
            .limit(pageable.getPageSize())
            .fetch();

        Long postCounts = jpaQueryFactory.select(Wildcard.count)
            .from(post)
            .where(
                searchByTitle(searchPostAdmin.getTitle()),
                searchByContent(searchPostAdmin.getContent()),
                searchByUserId(searchPostAdmin.getUserId()),
                searchByCreated(searchPostAdmin.getCreatedStarted(),
                    searchPostAdmin.getCreatedEnded())
            )
            .fetch().get(0);

        return new PageImpl<>(ResponsePost.of(posts), pageable, postCounts);
    }
    
}