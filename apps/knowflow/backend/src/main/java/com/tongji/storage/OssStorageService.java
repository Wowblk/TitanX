package com.tongji.storage;

import com.aliyun.oss.OSS;
import com.aliyun.oss.OSSClientBuilder;
import com.aliyun.oss.model.PutObjectRequest;
import com.aliyun.oss.HttpMethod;
import com.aliyun.oss.model.GeneratePresignedUrlRequest;
import com.tongji.storage.config.OssProperties;
import com.tongji.common.exception.BusinessException;
import com.tongji.common.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.net.URL;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class OssStorageService {

    private final OssProperties props;

    public String uploadAvatar(long userId, MultipartFile file) {
        String original = file.getOriginalFilename();
        String ext = "";
        if (original != null && original.contains(".")) {
            ext = original.substring(original.lastIndexOf('.'));
        }
        String objectKey = props.getFolder() + "/" + userId + "-" + Instant.now().toEpochMilli() + ext;

        if (isLocalMode()) {
            try {
                saveLocalObject(objectKey, file.getInputStream());
                return publicUrl(objectKey);
            } catch (IOException e) {
                throw new BusinessException(ErrorCode.BAD_REQUEST, "头像文件读取失败");
            }
        }

        ensureConfigured();
        OSS client = new OSSClientBuilder().build(props.getEndpoint(), props.getAccessKeyId(), props.getAccessKeySecret());

        try {
            PutObjectRequest request = new PutObjectRequest(props.getBucket(), objectKey, file.getInputStream());
            client.putObject(request);
        } catch (IOException e) {
            throw new BusinessException(ErrorCode.BAD_REQUEST, "头像文件读取失败");
        } finally {
            client.shutdown();
        }

        return publicUrl(objectKey);
    }

    private String publicOssUrl(String objectKey) {
        if (props.getPublicDomain() != null && !props.getPublicDomain().isBlank()) {
            return props.getPublicDomain().replaceAll("/$", "") + "/" + objectKey;
        }
        return "https://" + props.getBucket() + "." + props.getEndpoint() + "/" + objectKey;
    }

    /**
     * 生成用于直传的 PUT 预签名 URL。
     * 客户端必须在上传时设置与签名一致的 Content-Type。
     *
     * @param objectKey 目标对象键
     * @param contentType 上传内容类型（如 text/markdown, image/png）
     * @param expiresInSeconds 有效期秒数（建议 300-900）
     * @return 可直接用于 PUT 上传的预签名 URL
     */
    public String generatePresignedPutUrl(String objectKey, String contentType, int expiresInSeconds) {
        if (isLocalMode()) {
            return "/api/v1/storage/local-upload?objectKey=" + URLEncoder.encode(objectKey, StandardCharsets.UTF_8);
        }

        ensureConfigured();
        OSS client = new OSSClientBuilder().build(props.getEndpoint(), props.getAccessKeyId(), props.getAccessKeySecret());
        try {
            Date expiration = new Date(System.currentTimeMillis() + expiresInSeconds * 1000L);
            GeneratePresignedUrlRequest request = new GeneratePresignedUrlRequest(props.getBucket(), objectKey, HttpMethod.PUT);
            request.setExpiration(expiration);
            if (contentType != null && !contentType.isBlank()) {
                request.setContentType(contentType);
            }
            URL url = client.generatePresignedUrl(request);
            return url.toString();
        } finally {
            client.shutdown();
        }
    }

    public String saveLocalObject(String objectKey, InputStream inputStream) {
        if (!isLocalMode()) {
            throw new BusinessException(ErrorCode.BAD_REQUEST, "本地存储模式未启用");
        }
        Path root = Path.of(props.getLocalRoot()).toAbsolutePath().normalize();
        Path target = root.resolve(objectKey).normalize();
        if (!target.startsWith(root)) {
            throw new BusinessException(ErrorCode.BAD_REQUEST, "objectKey 非法");
        }
        try {
            Files.createDirectories(target.getParent());
            long size;
            try (OutputStream outputStream = Files.newOutputStream(target)) {
                size = inputStream.transferTo(outputStream);
            }
            return "\"" + Long.toHexString(size) + "-" + Long.toHexString(Files.getLastModifiedTime(target).toMillis()) + "\"";
        } catch (IOException e) {
            throw new BusinessException(ErrorCode.BAD_REQUEST, "本地文件保存失败");
        }
    }

    public Path resolveLocalObject(String objectKey) {
        Path root = Path.of(props.getLocalRoot()).toAbsolutePath().normalize();
        Path target = root.resolve(objectKey).normalize();
        if (!target.startsWith(root) || !Files.isRegularFile(target)) {
            throw new BusinessException(ErrorCode.BAD_REQUEST, "文件不存在");
        }
        return target;
    }

    public String publicUrl(String objectKey) {
        if (isLocalMode()) {
            return props.getLocalPublicPrefix().replaceAll("/$", "") + "?objectKey=" + URLEncoder.encode(objectKey, StandardCharsets.UTF_8);
        }
        return publicOssUrl(objectKey);
    }

    private boolean isLocalMode() {
        return "local".equalsIgnoreCase(props.getMode());
    }

    private void ensureConfigured() {
        if (props.getEndpoint() == null || props.getAccessKeyId() == null || props.getAccessKeySecret() == null || props.getBucket() == null) {
            throw new BusinessException(ErrorCode.BAD_REQUEST, "对象存储未配置");
        }
    }
}
