package com.tongji.knowpost.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tongji.knowpost.api.dto.DraftPageResponse;
import com.tongji.knowpost.mapper.KnowPostMapper;
import com.tongji.knowpost.model.KnowPost;
import com.tongji.knowpost.model.KnowPostDetailRow;
import com.tongji.knowpost.model.KnowPostFeedRow;
import com.tongji.knowpost.service.impl.KnowPostServiceImpl;
import com.tongji.storage.config.OssProperties;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class KnowPostServiceImplDraftTest {

    @Test
    void listDraftsReturnsDraftMetadataAndHasMore() {
        KnowPost first = KnowPost.builder()
                .id(101L)
                .title("TitanX 草稿")
                .description("Agent 框架草稿")
                .tags("[\"agent\",\"gateway\"]")
                .imgUrls("[\"/api/v1/storage/local-files?objectKey=a.png\"]")
                .visible("private")
                .contentUrl("/api/v1/storage/local-files?objectKey=content.md")
                .updateTime(Instant.parse("2026-04-26T10:00:00Z"))
                .createTime(Instant.parse("2026-04-25T10:00:00Z"))
                .build();
        KnowPost second = KnowPost.builder()
                .id(102L)
                .title("extra")
                .build();
        FakeKnowPostMapper mapper = new FakeKnowPostMapper(List.of(first, second));

        KnowPostServiceImpl service = new KnowPostServiceImpl(
                mapper,
                null,
                new ObjectMapper(),
                new OssProperties(),
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );

        DraftPageResponse response = service.listDrafts(7L, 1, 1);

        assertThat(mapper.creatorId).isEqualTo(7L);
        assertThat(mapper.limit).isEqualTo(2);
        assertThat(mapper.offset).isZero();
        assertThat(response.hasMore()).isTrue();
        assertThat(response.items()).hasSize(1);
        assertThat(response.items().getFirst().id()).isEqualTo("101");
        assertThat(response.items().getFirst().title()).isEqualTo("TitanX 草稿");
        assertThat(response.items().getFirst().tags()).containsExactly("agent", "gateway");
        assertThat(response.items().getFirst().images()).containsExactly("/api/v1/storage/local-files?objectKey=a.png");
        assertThat(response.items().getFirst().contentUrl()).isEqualTo("/api/v1/storage/local-files?objectKey=content.md");
    }

    private static final class FakeKnowPostMapper implements KnowPostMapper {
        private final List<KnowPost> drafts;
        private long creatorId;
        private int limit;
        private int offset;

        private FakeKnowPostMapper(List<KnowPost> drafts) {
            this.drafts = drafts;
        }

        @Override
        public void insertDraft(KnowPost post) {
        }

        @Override
        public KnowPost findById(Long id) {
            return null;
        }

        @Override
        public int updateContent(KnowPost post) {
            return 0;
        }

        @Override
        public int updateMetadata(KnowPost post) {
            return 0;
        }

        @Override
        public int publish(Long id, Long creatorId) {
            return 0;
        }

        @Override
        public List<KnowPostFeedRow> listFeedPublic(int limit, int offset) {
            return List.of();
        }

        @Override
        public List<KnowPostFeedRow> listMyPublished(long creatorId, int limit, int offset) {
            return List.of();
        }

        @Override
        public List<KnowPost> listMyDrafts(long creatorId, int limit, int offset) {
            this.creatorId = creatorId;
            this.limit = limit;
            this.offset = offset;
            return drafts;
        }

        @Override
        public int updateTop(Long id, Long creatorId, Boolean isTop) {
            return 0;
        }

        @Override
        public int updateVisibility(Long id, Long creatorId, String visible) {
            return 0;
        }

        @Override
        public int softDelete(Long id, Long creatorId) {
            return 0;
        }

        @Override
        public KnowPostDetailRow findDetailById(Long id) {
            return null;
        }

        @Override
        public long countMyPublished(long creatorId) {
            return 0;
        }

        @Override
        public List<Long> listMyPublishedIds(long creatorId) {
            return List.of();
        }
    }
}
