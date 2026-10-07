package com.tongji.storage.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "oss")
public class OssProperties {
    private String mode = "local"; // local | oss
    private String localRoot = "data/uploads";
    private String localPublicPrefix = "/api/v1/storage/local-files";
    private String endpoint;
    private String accessKeyId;
    private String accessKeySecret;
    private String bucket;
    private String publicDomain; // 可选：如自定义 CDN 域名
    private String folder = "avatars"; // 默认上传目录
}
