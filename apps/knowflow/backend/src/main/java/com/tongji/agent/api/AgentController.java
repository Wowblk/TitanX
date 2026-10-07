package com.tongji.agent.api;

import com.tongji.agent.api.dto.AgentChatRequest;
import com.tongji.agent.api.dto.AgentDraftToolRequest;
import com.tongji.agent.api.dto.AgentDraftToolResponse;
import com.tongji.agent.service.AgentGatewayService;
import com.tongji.agent.service.AgentToolService;
import com.tongji.auth.token.JwtService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

@RestController
@RequestMapping("/api/v1/agent")
@Validated
@RequiredArgsConstructor
public class AgentController {

    private final AgentGatewayService agentGatewayService;
    private final AgentToolService agentToolService;
    private final JwtService jwtService;

    @PostMapping(path = "/chat", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public StreamingResponseBody chat(@Valid @RequestBody AgentChatRequest request,
                                      @AuthenticationPrincipal Jwt jwt) {
        long userId = jwtService.extractUserId(jwt);
        return agentGatewayService.streamChat(request, jwt, userId);
    }

    @PostMapping(path = "/tools/drafts", produces = MediaType.APPLICATION_JSON_VALUE)
    public AgentDraftToolResponse createDraft(@Valid @RequestBody AgentDraftToolRequest request,
                                              @AuthenticationPrincipal Jwt jwt) {
        long userId = jwtService.extractUserId(jwt);
        return agentToolService.createDraft(userId, request);
    }
}
