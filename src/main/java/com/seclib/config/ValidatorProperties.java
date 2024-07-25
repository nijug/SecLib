package com.seclib.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Configuration
@ConfigurationProperties(prefix = "validator")
public class ValidatorProperties {

    private final Patterns patterns = new Patterns();

    @Setter
    @Getter
    public static class Patterns {
        private String sqlInjection = "(?:')|(?:--)|(/\\*(?:.|[\\n\\r])*?\\*/)|" +
                "(\\b(select|update|delete|insert|drop|exec|execute|alter|create|grant|use|truncate|declare|xp_)\\b)";
        private String xss = "<script>(.*?)</script>|" +
                "src\\s*=\\s*[\\\"\\']?javascript:[^\\\"\\'>\\s]*[\\\"\\']?|" +
                "(on\\w+\\s*=\\s*[\\\"\\']?[^\\\"\\'>\\s]*[\\\"\\']?)|" +
                "<iframe(.*?)>|" +
                "<img(.*?)onerror\\s*=\\s*['\"]?[^'\"\\s]*['\"]?";
        private String allowedHtmlTags = "<\\/?(b|i|u|strong|em|p|br|a|img)(\\s+[^>]*)?>";
        private String javascriptUrl = "href\\s*=\\s*[\\\"\\']?javascript:[^\\\"\\'>\\s]*[\\\"\\']?";

    }

}